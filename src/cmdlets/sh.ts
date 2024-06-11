import { CmdLet } from '../commands/cmdlet.js';
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
  private pWaitPid: NativePointer | null = null;

  public override runSync(tokens: Token[]): Var {
    throw new Error("can't run in synchronous mode");
  }

  public override async run(tokens: Token[]): Promise<Var> {
    if (tokens.length !== 0) {
      this.usage();
      return Var.ZERO;
    }
   
    if (
      this.pPipe === null ||
      this.pFork === null ||
      this.pClose === null ||
      this.pDup2 === null ||
      this.pGetEnv == null ||
      this.pExecV == null ||
      this.pWaitPid == null
    )
      throw new Error('failed to find necessary native functions');

    // char *getenv(const char *name);
    const fnGetEnv = new SystemFunction(this.pGetEnv, 'pointer', ['pointer']);
    // int pipe(int pipefd[2]);
    const fnPipe = new SystemFunction(this.pPipe, 'int', ['pointer']);
    // pid_t fork(void);
    const fnFork = new SystemFunction(this.pFork, 'int', []);
    // int close(int fd);
    const fnClose = new SystemFunction(this.pClose, 'int', ['int']);
    // int dup2(int oldfd, int newfd);
    const fnDup2 = new SystemFunction(this.pDup2, 'int', ['int', 'int']);
    // int execv(const char *path, char *const argv[]);
    const fnExecV = new SystemFunction(this.pExecV, 'int', [
      'pointer',
      'pointer',
    ]);
    // pid_t waitpid(pid_t pid, int *status, int options);
    const fnWaitPid = new SystemFunction(this.pWaitPid, 'int', [
      'int',
      'pointer',
      'int',
    ]);

    const shell = Memory.allocUtf8String('SHELL');
    const { value: shellVar, errno: getenvErrno } = fnGetEnv(
      shell,
    ) as UnixSystemFunctionResult<NativePointer>;
    if (shellVar.equals(ptr(0)))
      throw new Error(`failed to getenv("SHELL"), errno: ${getenvErrno}`);

    Output.writeln(`SHELL: ${shellVar.readUtf8String()}`, true);

    const toChildPipes = Memory.alloc(INT_SIZE * 2);
    const { value: pipeChildRet, errno: pipeChildErrno } = fnPipe(
      toChildPipes,
    ) as UnixSystemFunctionResult<number>;
    if (pipeChildRet !== 0)
      throw new Error(`failed to pipe(child), errno: ${pipeChildErrno}`);

    const toParentPipes = Memory.alloc(INT_SIZE * 2);
    const { value: pipeParentRet, errno: pipeParentErrno } = fnPipe(
      toParentPipes,
    ) as UnixSystemFunctionResult<number>;
    if (pipeParentRet !== 0)
      throw new Error(`failed to pipe, errno: ${pipeParentErrno}`);

    const { value: forkRet, errno: forkErrno } =
      fnFork() as UnixSystemFunctionResult<number>;
    if (forkRet < 0) throw new Error(`failed to fork, errno: ${forkErrno}`);

    if (forkRet === 0) {
      // child
      const { value: closeChildRet, errno: closeChildErrno } = fnClose(
        toChildPipes.add(PIPE_WRITE_OFFSET).readInt(),
      ) as UnixSystemFunctionResult<number>;
      if (closeChildRet !== 0)
        throw new Error(`failed to close(child), errno: ${closeChildErrno}`);

      const { value: closeParentRet, errno: closeParentErrno } = fnClose(
        toParentPipes.add(PIPE_READ_OFFSET).readInt(),
      ) as UnixSystemFunctionResult<number>;
      if (closeParentRet !== 0)
        throw new Error(`failed to close(parent), errno: ${closeParentErrno}`);

      const { value: dup2InRet, errno: dup2InErrno } = fnDup2(
        toChildPipes.add(PIPE_READ_OFFSET).readInt(),
        STDIN_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2InRet !== STDIN_FILENO)
        throw new Error(`failed to dup2(stdin), errno: ${dup2InErrno}`);

      const { value: dup2OutRet, errno: dup2OutErrno } = fnDup2(
        toParentPipes.add(PIPE_WRITE_OFFSET).readInt(),
        STDOUT_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2OutRet !== STDOUT_FILENO)
        throw new Error(`failed to dup2(stdout), errno: ${dup2OutErrno}`);

      const { value: dup2ErrRet, errno: dup2ErrErrno } = fnDup2(
        toParentPipes.add(PIPE_WRITE_OFFSET).readInt(),
        STDERR_FILENO,
      ) as UnixSystemFunctionResult<number>;
      if (dup2ErrRet !== STDERR_FILENO)
        throw new Error(`failed to dup2(stderr), errno: ${dup2ErrErrno}`);

      const argv = Memory.alloc(Process.pointerSize * 2);
      const cmd = Memory.allocUtf8String('/usr/bin/ls');
      argv.writePointer(cmd);
      argv.add(Process.pointerSize).writePointer(ptr(0));

      const { value: execvRet, errno: execvErrno } = fnExecV(
        cmd,
        argv,
      ) as UnixSystemFunctionResult<number>;
      if (execvRet !== 0)
        throw new Error(`failed to execv, errno: ${execvErrno}`);

      // unreachable
    } else {
      // parent
      Output.writeln(`child pid: ${forkRet}`, true);
      const { value: closeChildRet, errno: closeChildErrno } = fnClose(
        toChildPipes.add(PIPE_READ_OFFSET).readInt(),
      ) as UnixSystemFunctionResult<number>;
      if (closeChildRet !== 0)
        throw new Error(`failed to close(child), errno: ${closeChildErrno}`);

      const { value: closeParentRet, errno: closeParentErrno } = fnClose(
        toParentPipes.add(PIPE_WRITE_OFFSET).readInt(),
      ) as UnixSystemFunctionResult<number>;
      if (closeParentRet !== 0)
        throw new Error(`failed to close(parent), errno: ${closeParentErrno}`);

      const input = new UnixInputStream(
        toParentPipes.add(PIPE_READ_OFFSET).readInt(),
        { autoClose: true },
      );
      // const output = new UnixOutputStream(
      //   toChildPipes.add(PIPE_WRITE_OFFSET).readInt(),
      //   { autoClose: true },
      // );

      const pStatus = Memory.alloc(INT_SIZE);
      const { value: waitRet, errno: waitErrno } = fnWaitPid(
        forkRet,
        pStatus,
        0,
      ) as UnixSystemFunctionResult<number>;
      if (waitRet < 0)
        throw new Error(`failed to waitpid ${waitRet}, errno: ${waitErrno}`);

      if (waitRet !== forkRet)
        throw new Error(`waitpid exited abnormally, status: ${waitRet}`);

      const status = pStatus.readInt();
      if (this.wifExited(status)) {
        const exitStatus = this.wExitStatus(status);
        Output.writeln(`exit status: ${exitStatus}`);
      } else if (this.wifSignalled(status)) {
        const termSig = this.wTermSig(status);
        Output.writeln(`terminated by signal: ${termSig}`);
      }

      for (
        let buf = await input.read(READ_SIZE);
        buf.byteLength !== 0;
        buf = await input.read(READ_SIZE)
      ) {
        const str: string = Format.toTextString(buf);
        Output.write(str);
      }
    }
    return Var.ZERO;
  }

  private wifExited(status: number): boolean {
    return (status & 0xff00) >> 8 === 0;
  }

  private wExitStatus(status: number): number {
    return (status & 0xff00) >> 8;
  }

  private wifSignalled(status: number): boolean {
    return (status & 0xff00) >> 8 === 0x7f;
  }

  private wTermSig(status: number): number {
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
        this.pWaitPid = Module.findExportByName(null, 'waitpid');

        if (
          this.pGetEnv == null ||
          this.pPipe === null ||
          this.pFork === null ||
          this.pClose === null ||
          this.pDup2 === null ||
          this.pExecV == null ||
          this.pWaitPid == null
        )
          return false;
        break;
      case 'windows':
      case 'barebone':
      default:
        return false;
    }

    return true;
  }
}
