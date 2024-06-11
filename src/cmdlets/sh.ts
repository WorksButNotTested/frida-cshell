import { CmdLet } from '../commands/cmdlet.js';
import { Input, InputInterceptRaw } from '../io/input.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';

const INT_SIZE: number = 4;
const PIPE_READ_OFFSET: number = 0;
const PIPE_WRITE_OFFSET: number = 4;
const STDIN_FILENO: number = 0;
const STDOUT_FILENO: number = 1;
const STDERR_FILENO: number = 2;
const READ_SIZE: number = 4096;
const WNOHANG: number = 1;

type Pipe = { readFd: number; writeFd: number };

const USAGE: string = `Usage: fd
sh - run a shell
`;

export class ShCmdLet extends CmdLet {
  name = 'sh';
  category = 'misc';
  help = 'run a shell';

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

  public override runSync(tokens: Token[]): Var {
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

    Output.writeln(`SHELL: ${shellVar.readUtf8String()}`, true);
    const childPipe = this.createPipe();
    const parentPipe = this.createPipe();

    const { value: childPid, errno: forkErrno } =
      this.fnFork() as UnixSystemFunctionResult<number>;
    if (childPid < 0) throw new Error(`failed to fork, errno: ${forkErrno}`);

    if (childPid === 0) {
      try {
        this.runChild(childPipe, parentPipe);
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
    const pipes = Memory.alloc(INT_SIZE * 2);
    const { value: pipeRet, errno: pipeErrno } = this.fnPipe(
      pipes,
    ) as UnixSystemFunctionResult<number>;
    if (pipeRet !== 0) throw new Error(`failed to pipe, errno: ${pipeErrno}`);
    const readFd = pipes.add(PIPE_READ_OFFSET).readInt();
    const writeFd = pipes.add(PIPE_WRITE_OFFSET).readInt();
    return { readFd, writeFd };
  }

  private runChild(childPipe: Pipe, parentPipe: Pipe) {
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
        STDIN_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2InRet !== STDIN_FILENO)
        throw new Error(`failed to dup2(stdin), errno: ${dup2InErrno}`);

      const { value: dup2OutRet, errno: dup2OutErrno } = this.fnDup2(
        toParentWriteFd,
        STDOUT_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2OutRet !== STDOUT_FILENO)
        throw new Error(`failed to dup2(stdout), errno: ${dup2OutErrno}`);

      const { value: dup2ErrRet, errno: dup2ErrErrno } = this.fnDup2(
        toParentWriteFd,
        STDERR_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2ErrRet !== STDERR_FILENO)
        throw new Error(`failed to dup2(stderr), errno: ${dup2ErrErrno}`);

      const cmd = '/usr/bin/ping';
      const cmdPtr = Memory.allocUtf8String(cmd);
      const args = [cmd, '-c3', 'localhost'];
      const argPtrs: NativePointer[] = Array.from(args).map(arg =>
        Memory.allocUtf8String(arg),
      );
      argPtrs.push(ptr(0));
      const argv = Memory.alloc(Process.pointerSize * argPtrs.length);
      for (const [idx, ptr] of argPtrs.entries()) {
        argv.add(Process.pointerSize * idx).writePointer(ptr);
      }

      const { value: execvRet, errno: execvErrno } = this.fnExecV(
        cmdPtr,
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
      if (
        this.fnClose === null ||
        this.fnWaitPid === null
      )
        throw new Error('failed to find necessary native functions');

      Output.writeln(`child pid: ${childPid}`, true);
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
        abort() {},
      };

      Input.setInterceptRaw(onRaw);

      Output.writeln(`reading pid: ${childPid}`, true);

      for (
        let buf = await input.read(READ_SIZE);
        buf.byteLength !== 0;
        buf = await input.read(READ_SIZE)
      ) {
        const str: string = Format.toTextString(buf);
        Output.write(str);
      }

      Output.writeln(`waiting pid: ${childPid}`, true);

      const pStatus = Memory.alloc(INT_SIZE);

      const { value: waitRet, errno: waitErrno } = this.fnWaitPid(
        childPid,
        pStatus,
        WNOHANG,
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
    Output.write(USAGE);
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
