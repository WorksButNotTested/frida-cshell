import { CmdLet } from '../../commands/cmdlet.js';
import { Input, InputInterceptRaw } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Format } from '../../misc/format.js';
import { Var } from '../../vars/var.js';

type Pipe = { readFd: number; writeFd: number };

export class ShCmdLet extends CmdLet {
  name = 'sh';
  category = 'misc';
  help = 'run a shell';

  private static readonly USAGE: string = `Usage: fd
sh - run a shell`;

  private static readonly INT_SIZE: number = 4;
  private static readonly PIPE_READ_OFFSET: number = 0;
  private static readonly PIPE_WRITE_OFFSET: number = 4;
  private static readonly STDIN_FILENO: number = 0;
  private static readonly STDOUT_FILENO: number = 1;
  private static readonly STDERR_FILENO: number = 2;
  private static readonly READ_SIZE: number = 4096;
  private static readonly WNOHANG: number = 1;

  private pGetEnv: NativePointer | null = null;
  private pPipe: NativePointer | null = null;
  private pFork: NativePointer | null = null;
  private pClose: NativePointer | null = null;
  private pDup2: NativePointer | null = null;
  private pExecV: NativePointer | null = null;
  private pExit: NativePointer | null = null;
  private pWaitPid: NativePointer | null = null;

  // char *getenv(const char *name);
  private fnGetEnv: SystemFunction<NativePointer, [NativePointer]> | null =
    null;
  // int pipe(int pipefd[2]);
  private fnPipe: SystemFunction<number, [NativePointer]> | null = null;
  // pid_t fork(void);
  private fnFork: SystemFunction<number, []> | null = null;
  // int close(int fd);
  private fnClose: SystemFunction<number, [number]> | null = null;
  // int dup2(int oldfd, int newfd);
  private fnDup2: SystemFunction<number, [number, number]> | null = null;
  // int execv(const char *path, char *const argv[]);
  private fnExecV: SystemFunction<
    number,
    [NativePointer, NativePointer]
  > | null = null;
  // pid_t waitpid(pid_t pid, int *status, int options);
  private fnWaitPid: SystemFunction<
    number,
    [number, NativePointer, number]
  > | null = null;
  // void exit(int status);
  private fnExit: SystemFunction<void, [number]> | null = null;

  public override runSync(_tokens: Token[]): Var {
    throw new Error("can't run in synchronous mode");
  }

  public override async run(tokens: Token[]): Promise<Var> {
    if (tokens.length !== 0) {
      this.usage();
      return Var.ZERO;
    }

    if (
      this.fnGetEnv == null ||
      this.fnPipe === null ||
      this.fnFork === null ||
      this.fnClose === null ||
      this.fnDup2 === null ||
      this.fnExecV == null ||
      this.fnWaitPid == null ||
      this.fnExit == null
    )
      throw new Error('failed to find necessary native functions');

    const shell = Memory.allocUtf8String('SHELL');
    const { value: shellVar, errno: getenvErrno } = this.fnGetEnv(
      shell,
    ) as UnixSystemFunctionResult<NativePointer>;
    if (shellVar.equals(ptr(0)))
      throw new Error(`failed to getenv("SHELL"), errno: ${getenvErrno}`);

    const shellPath = shellVar.readUtf8String();
    Output.debug(`SHELL: ${shellPath}`);

    if (shellPath === null) throw new Error('failed to read SHELL');

    const childPipe = this.createPipe();
    const parentPipe = this.createPipe();

    const { value: childPid, errno: forkErrno } =
      this.fnFork() as UnixSystemFunctionResult<number>;
    if (childPid < 0) throw new Error(`failed to fork, errno: ${forkErrno}`);

    if (childPid === 0) {
      try {
        const cmd = [shellPath, '-i'];
        this.runChild(cmd, childPipe, parentPipe);
      } finally {
        this.fnExit(1);
      }
    } else {
      await this.runParent(childPid, childPipe, parentPipe);
    }
    return Var.ZERO;
  }

  private createPipe(): Pipe {
    if (this.fnPipe === null)
      throw new Error('failed to find necessary native functions');
    const pipes = Memory.alloc(ShCmdLet.INT_SIZE * 2);
    const { value: pipeRet, errno: pipeErrno } = this.fnPipe(
      pipes,
    ) as UnixSystemFunctionResult<number>;
    if (pipeRet !== 0) throw new Error(`failed to pipe, errno: ${pipeErrno}`);
    const readFd = pipes.add(ShCmdLet.PIPE_READ_OFFSET).readInt();
    const writeFd = pipes.add(ShCmdLet.PIPE_WRITE_OFFSET).readInt();
    return { readFd, writeFd };
  }

  private runChild(command: string[], childPipe: Pipe, parentPipe: Pipe) {
    const { readFd: toChildReadFd, writeFd: toChildWriteFd } = childPipe;
    const { readFd: toParentReadFd, writeFd: toParentWriteFd } = parentPipe;
    try {
      if (
        this.fnGetEnv == null ||
        this.fnClose === null ||
        this.fnDup2 === null ||
        this.fnExecV == null ||
        this.fnExit == null
      )
        throw new Error('failed to find necessary native functions');

      const { value: closeChildRet, errno: closeChildErrno } = this.fnClose(
        toChildWriteFd,
      ) as UnixSystemFunctionResult<number>;
      if (closeChildRet !== 0)
        throw new Error(`failed to close(child), errno: ${closeChildErrno}`);

      const { value: closeParentRet, errno: closeParentErrno } = this.fnClose(
        toParentReadFd,
      ) as UnixSystemFunctionResult<number>;
      if (closeParentRet !== 0)
        throw new Error(`failed to close(parent), errno: ${closeParentErrno}`);

      const { value: dup2InRet, errno: dup2InErrno } = this.fnDup2(
        toChildReadFd,
        ShCmdLet.STDIN_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2InRet !== ShCmdLet.STDIN_FILENO)
        throw new Error(`failed to dup2(stdin), errno: ${dup2InErrno}`);

      const { value: dup2OutRet, errno: dup2OutErrno } = this.fnDup2(
        toParentWriteFd,
        ShCmdLet.STDOUT_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2OutRet !== ShCmdLet.STDOUT_FILENO)
        throw new Error(`failed to dup2(stdout), errno: ${dup2OutErrno}`);

      const { value: dup2ErrRet, errno: dup2ErrErrno } = this.fnDup2(
        toParentWriteFd,
        ShCmdLet.STDERR_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2ErrRet !== ShCmdLet.STDERR_FILENO)
        throw new Error(`failed to dup2(stderr), errno: ${dup2ErrErrno}`);

      if (command.length === 0) throw new Error('empty command');
      const args: NativePointer[] = Array.from(command).map(arg =>
        Memory.allocUtf8String(arg),
      );
      args.push(ptr(0));
      const argv = Memory.alloc(Process.pointerSize * args.length);
      for (const [idx, ptr] of args.entries()) {
        argv.add(Process.pointerSize * idx).writePointer(ptr);
      }

      const { value: execvRet, errno: execvErrno } = this.fnExecV(
        args[0] as NativePointer,
        argv,
      ) as UnixSystemFunctionResult<number>;
      if (execvRet !== 0)
        throw new Error(`failed to execv, errno: ${execvErrno}`);
    } catch (error) {
      const output = new UnixOutputStream(toParentWriteFd);
      if (error instanceof Error) {
        output.write(Format.toByteArray(`ERROR: ${error.message}`));
        output.write(Format.toByteArray(`${error.stack}`));
      } else {
        output.write(Format.toByteArray('Unknown error'));
      }
      output.close();
    }
  }

  private async runParent(childPid: number, childPipe: Pipe, parentPipe: Pipe) {
    const { readFd: toChildReadFd, writeFd: toChildWriteFd } = childPipe;
    const { readFd: toParentReadFd, writeFd: toParentWriteFd } = parentPipe;
    try {
      if (this.fnClose === null || this.fnWaitPid === null)
        throw new Error('failed to find necessary native functions');

      Output.debug(`child pid: ${childPid}`);
      const { value: closeChildRet, errno: closeChildErrno } = this.fnClose(
        toChildReadFd,
      ) as UnixSystemFunctionResult<number>;
      if (closeChildRet !== 0)
        throw new Error(`failed to close(child), errno: ${closeChildErrno}`);

      const { value: closeParentRet, errno: closeParentErrno } = this.fnClose(
        toParentWriteFd,
      ) as UnixSystemFunctionResult<number>;
      if (closeParentRet !== 0)
        throw new Error(`failed to close(parent), errno: ${closeParentErrno}`);

      const input = new UnixInputStream(toParentReadFd, { autoClose: true });

      const output = new UnixOutputStream(toChildWriteFd, {
        autoClose: true,
      });

      const onRaw: InputInterceptRaw = {
        addRaw(raw: string) {
          output.write(Format.toByteArray(raw));
        },
        abortRaw() {},
      };

      Input.setInterceptRaw(onRaw);

      Output.debug(`reading pid: ${childPid}`);

      for (
        let buf = await input.read(ShCmdLet.READ_SIZE);
        buf.byteLength !== 0;
        buf = await input.read(ShCmdLet.READ_SIZE)
      ) {
        const str: string = Format.toTextString(buf);
        Output.write(str);
      }

      Output.debug(`waiting pid: ${childPid}`);

      const pStatus = Memory.alloc(ShCmdLet.INT_SIZE);

      const { value: waitRet, errno: waitErrno } = this.fnWaitPid(
        childPid,
        pStatus,
        ShCmdLet.WNOHANG,
      ) as UnixSystemFunctionResult<number>;
      if (waitRet < 0)
        throw new Error(`failed to waitpid ${waitRet}, errno: ${waitErrno}`);

      if (waitRet !== childPid) throw new Error(`failed to waitpid ${waitRet}`);

      const status = pStatus.readInt();
      if (ShCmdLet.wifExited(status)) {
        const exitStatus = ShCmdLet.wExitStatus(status);
        Output.writeln(`exit status: ${exitStatus}`);
      } else if (ShCmdLet.wifSignalled(status)) {
        const termSig = ShCmdLet.wTermSig(status);
        Output.writeln(`terminated by signal: ${termSig}`);
      }
    } finally {
      Input.setInterceptRaw(null);
    }
  }

  private static wifExited(status: number): boolean {
    return (status & 0xff00) >> 8 === 0;
  }

  private static wExitStatus(status: number): number {
    return (status & 0xff00) >> 8;
  }

  private static wifSignalled(status: number): boolean {
    return (status & 0xff00) >> 8 === 0x7f;
  }

  private static wTermSig(status: number): number {
    return status & 0x7f;
  }

  public usage(): Var {
    Output.writeln(ShCmdLet.USAGE);
    return Var.ZERO;
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'darwin':
      case 'freebsd':
      case 'linux':
      case 'qnx':
        this.pGetEnv = Module.findExportByName(null, 'getenv');
        this.pPipe = Module.findExportByName(null, 'pipe');
        this.pFork = Module.findExportByName(null, 'fork');
        this.pClose = Module.findExportByName(null, 'close');
        this.pDup2 = Module.findExportByName(null, 'dup2');
        this.pExecV = Module.findExportByName(null, 'execv');
        this.pExit = Module.findExportByName(null, 'exit');
        this.pWaitPid = Module.findExportByName(null, 'waitpid');

        if (
          this.pGetEnv == null ||
          this.pPipe === null ||
          this.pFork === null ||
          this.pClose === null ||
          this.pDup2 === null ||
          this.pExecV == null ||
          this.pExit == null ||
          this.pWaitPid == null
        )
          return false;

        // char *getenv(const char *name);
        this.fnGetEnv = new SystemFunction(this.pGetEnv, 'pointer', [
          'pointer',
        ]);
        // int pipe(int pipefd[2]);
        this.fnPipe = new SystemFunction(this.pPipe, 'int', ['pointer']);
        // pid_t fork(void);
        this.fnFork = new SystemFunction(this.pFork, 'int', []);
        // int close(int fd);
        this.fnClose = new SystemFunction(this.pClose, 'int', ['int']);
        // int dup2(int oldfd, int newfd);
        this.fnDup2 = new SystemFunction(this.pDup2, 'int', ['int', 'int']);
        // int execv(const char *path, char *const argv[]);
        this.fnExecV = new SystemFunction(this.pExecV, 'int', [
          'pointer',
          'pointer',
        ]);
        // pid_t waitpid(pid_t pid, int *status, int options);
        this.fnWaitPid = new SystemFunction(this.pWaitPid, 'int', [
          'int',
          'pointer',
          'int',
        ]);
        // void exit(int status);
        this.fnExit = new SystemFunction(this.pExit, 'void', ['int']);

        break;
      case 'windows':
      case 'barebone':
      default:
        return false;
    }

    return true;
  }
}
