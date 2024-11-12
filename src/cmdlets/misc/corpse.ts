import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Exception } from '../../misc/exception.js';
import { Files } from '../../misc/files.js';
import { Format } from '../../misc/format.js';
import { Var } from '../../vars/var.js';

export class CorpseCmdLet extends CmdLetBase {
  name = 'corpse';
  category = 'misc';
  help = 'create a corpse file';

  private static readonly USAGE: string = `Usage: corpse
corpse - create a corpse file`;
  private static readonly RLIMIT_CORE: number = 4;
  private static readonly CORE_PATTERN: string =
    '/proc/sys/kernel/core_pattern';
  private static readonly INT_SIZE: number = 4;
  private static readonly CORE_DUMP_FILTER: string =
    '/proc/self/coredump_filter';
  private static readonly CORE_FILTER: UInt64 = uint64(0x1ff);
  private static readonly SIGABRT: number = 6;
  private static readonly SIGKILL: number = 9;
  private static readonly MAGIC: number = 0x7f454c46;
  private static readonly DEBUG_FILE_NAME: string = '/tmp/corpse.log';
  private static readonly WNOHANG: number = 0x00000001;

  private pGetrlimit: NativePointer | null = null;
  private pSetrlimit: NativePointer | null = null;
  private pFork: NativePointer | null = null;
  private pWaitPid: NativePointer | null = null;
  private pGetPid: NativePointer | null = null;
  private pKill: NativePointer | null = null;

  public runSync(tokens: Token[]): Var {
    if (tokens.length != 0) {
      Output.writeln(CorpseCmdLet.USAGE);
      return Var.ZERO;
    }

    const path = Files.getRandomFileName('corpse');

    this.createCorpse(path);

    Output.writeln(
      ['Created corpse file: ', Output.blue(path)].join(' '),
      true,
    );
    return Var.ZERO;
  }

  private createCorpse(path: string) {
    const currentCorePattern = this.setCorePattern(path);
    try {
      const limit = this.setrlimit({ softLimit: -1, hardLimit: -1 });
      try {
        const filter = this.setCoreDumpFilter(CorpseCmdLet.CORE_FILTER);
        try {
          const debugFileName = CorpseCmdLet.DEBUG_FILE_NAME;
          const debugFile = new File(debugFileName, 'w');
          const debugFunc = (msg: string) => {
            debugFile.write(`${msg}\n`);
            debugFile.flush();
          };
          Exception.propagate();
          try {
            this.fork(
              (pid: number) => {
                this.runParent(pid);
              },
              () => {
                this.runChild(debugFunc);
              },
            );
            this.checkCorpse(path);
          } finally {
            Exception.suppress();
            this.checkDebugFile(debugFileName);
          }
        } finally {
          this.setCoreDumpFilter(filter);
        }
      } finally {
        this.setrlimit(limit);
      }
    } finally {
      this.setCorePattern(currentCorePattern);
    }
  }

  private setCorePattern(newCorePattern: string): string {
    const currentCorePattern = File.readAllText(
      CorpseCmdLet.CORE_PATTERN,
    ).trimEnd();
    Output.debug(`current core pattern: ${currentCorePattern}`);
    File.writeAllText(CorpseCmdLet.CORE_PATTERN, newCorePattern);
    Output.debug(`set core pattern to: ${newCorePattern}`);
    return currentCorePattern;
  }

  private setrlimit(limit: {
    softLimit: number | Int64;
    hardLimit: number | Int64;
  }): { softLimit: number | Int64; hardLimit: number | Int64 } {
    if (this.pGetrlimit === null || this.pSetrlimit === null)
      throw new Error('failed to find necessary native functions');

    // int getrlimit(int resource, struct rlimit *rlim);
    const fnGetrlimit = new SystemFunction(this.pGetrlimit, 'int', [
      'int',
      'pointer',
    ]);

    // int setrlimit(int resource, const struct rlimit *rlim);
    const fnSetrlimit = new SystemFunction(this.pSetrlimit, 'int', [
      'int',
      'pointer',
    ]);

    const buffer = Memory.alloc(Process.pointerSize * 2);

    Output.debug('getting rlimit');
    const retGetRlimit = fnGetrlimit(
      CorpseCmdLet.RLIMIT_CORE,
      buffer,
    ) as UnixSystemFunctionResult<number>;
    if (retGetRlimit.value === -1) {
      throw new Error(`failed to getrlimit, errno: ${retGetRlimit.errno}`);
    }

    let cursor = buffer;
    const currentSoftLimit = cursor.readLong();
    cursor = cursor.add(Process.pointerSize);
    const currentHardLimit = cursor.readLong();
    cursor = cursor.add(Process.pointerSize);

    Output.debug(
      `got rlimit - soft: ${currentSoftLimit}, hard: ${currentHardLimit}`,
    );

    cursor = buffer;
    cursor.writeLong(limit.softLimit);
    cursor = cursor.add(Process.pointerSize);
    cursor.writeLong(limit.hardLimit);
    cursor = cursor.add(Process.pointerSize);

    Output.debug('setting rlimit');

    const retSetRlimit = fnSetrlimit(
      CorpseCmdLet.RLIMIT_CORE,
      buffer,
    ) as UnixSystemFunctionResult<number>;
    if (retSetRlimit.value === -1) {
      throw new Error(`failed to setrlimit, errno: ${retSetRlimit.errno}`);
    }

    Output.debug('set rlimit');

    return { softLimit: currentSoftLimit, hardLimit: currentHardLimit };
  }

  private setCoreDumpFilter(newFilter: UInt64): UInt64 {
    Output.debug('reading core filter');
    const currentFilterText = File.readAllText(
      CorpseCmdLet.CORE_DUMP_FILTER,
    ).trimEnd();
    Output.debug(`read core filter text: ${currentFilterText}`);
    const currentFilter = uint64(`0x${currentFilterText}`);
    Output.debug(`read core filter: ${currentFilter}`);
    Output.debug('setting core filter');
    File.writeAllText(CorpseCmdLet.CORE_DUMP_FILTER, `0x${newFilter}`);
    Output.debug('set core filter');
    return currentFilter;
  }

  private fork(
    parentCallback: (childPid: number) => void,
    childCallback: () => void,
  ): void {
    if (this.pFork === null)
      throw new Error('failed to find necessary native functions');

    /* pid_t fork(void); */
    const fnFork = new SystemFunction(this.pFork, 'int', []);

    Output.debug('forking');
    const retFork = fnFork() as UnixSystemFunctionResult<number>;
    if (retFork.value === -1) {
      throw new Error(`failed to fork, errno: ${retFork.errno}`);
    } else if (retFork.value === 0) {
      childCallback();
    } else {
      parentCallback(retFork.value);
    }
  }

  private runChild(debug: (msg: string) => void) {
    const pid = this.getpid();
    debug(`Creating corpse`);

    debug(`PID: ${pid}`);
    /* child */
    try {
      while (true) {
        Thread.sleep(0.1);
      }
    } catch (error) {
      if (error instanceof Error) {
        debug(`ERROR: ${error.message}`);
        debug(`${error.stack}`);
      } else {
        debug(`ERROR: Unknown error`);
      }
    } finally {
      debug(`Suicide`);
      this.kill(pid, CorpseCmdLet.SIGKILL);
    }
  }

  private runParent(pid: number) {
    Output.debug(`forked: in parent, child is: ${pid}`);

    for (let i = 0; i < 10; i++) {
      this.kill(pid, CorpseCmdLet.SIGABRT);

      const status = this.waitpid(pid);
      Output.debug(
        `status - exitStatus: ${status.exitStatus}, termSignal: ${status.termSignal}, stopped: ${status.stopped}`,
      );

      if (status.stopped) break;

      Thread.sleep(0.5);
    }

    Output.debug('Process aborted');
  }

  private getpid(): number {
    if (this.pGetPid === null)
      throw new Error('failed to find necessary native functions');

    /* pid_t getpid(void); */
    const fnGetPid = new SystemFunction(this.pGetPid, 'int', []);
    const retPid = fnGetPid() as UnixSystemFunctionResult<number>;
    return retPid.value;
  }

  private waitpid(pid: number): {
    exitStatus: number | null;
    termSignal: number | null;
    stopped: boolean;
  } {
    if (this.pWaitPid === null)
      throw new Error('failed to find necessary native functions');

    const pStatus = Memory.alloc(CorpseCmdLet.INT_SIZE);
    const fnWaitPid = new SystemFunction(this.pWaitPid, 'int', [
      'int',
      'pointer',
      'int',
    ]);
    Output.debug('waiting for child');
    const retWaitPid = fnWaitPid(
      pid,
      pStatus,
      CorpseCmdLet.WNOHANG,
    ) as UnixSystemFunctionResult<number>;

    Output.debug(
      `waited for child: ${retWaitPid.value}, errno: ${retWaitPid.errno}`,
    );

    if (retWaitPid.value === -1)
      throw new Error(`failed to waitpid, errno: ${retWaitPid.errno}`);

    if (retWaitPid.value === 0)
      return { exitStatus: null, termSignal: null, stopped: false };

    if (retWaitPid.value !== pid) throw new Error(`failed to waitpid ${pid}`);

    const status = pStatus.readInt();

    Output.debug(`waitpid: status: ${status}`);
    if (CorpseCmdLet.wifExited(status)) {
      const exitStatus = CorpseCmdLet.wExitStatus(status);
      Output.writeln(`exit status: ${exitStatus}`);
      return { exitStatus, termSignal: null, stopped: true };
    } else if (CorpseCmdLet.wifSignalled(status)) {
      const termSignal = CorpseCmdLet.wTermSig(status);
      Output.writeln(`terminated by signal: ${termSignal}`);
      return { exitStatus: null, termSignal, stopped: true };
    } else {
      throw new Error(`Failed to wait for pid: ${pid}, status: ${status}`);
    }
  }

  private kill(pid: number, signal: number) {
    if (this.pKill === null)
      throw new Error('failed to find necessary native functions');

    /* int kill(pid_t pid, int sig); */
    const fnKill = new SystemFunction(this.pKill, 'int', ['int', 'int']);

    Output.debug(`killing child: ${pid}, signal: ${signal}`);
    const killRet = fnKill(pid, signal) as UnixSystemFunctionResult<number>;
    if (killRet.value === -1) {
      throw new Error(`failed to kill, errno: ${killRet.errno}`);
    }

    Output.debug(`killed child: ${killRet.value}, errno: ${killRet.errno}`);
  }

  private static wExitStatus(status: number): number {
    return (status & 0xff00) >> 8;
  }

  private static wifExited(status: number): boolean {
    return CorpseCmdLet.wTermSig(status) === 0;
  }

  private static wifSignalled(status: number): boolean {
    const signal = CorpseCmdLet.wTermSig(status);
    return signal !== 0 && signal !== 0x7f;
  }

  private static wTermSig(status: number): number {
    return status & 0x7f;
  }

  private checkDebugFile(path: string) {
    const debugFile = new File(path, 'r');
    Output.debug('Child output...');
    for (
      let line = debugFile.readLine();
      line.length != 0;
      line = debugFile.readLine()
    ) {
      Output.debug(`\t${line.trimEnd()}`);
    }
    Output.debug('Child output complete');
  }

  private checkCorpse(path: string) {
    const corpse = new File(path, 'rb');

    corpse.seek(0, File.SEEK_END);
    const len = corpse.tell();
    Output.writeln(`Corpse is ${Format.toSize(len)}`);

    corpse.seek(0, File.SEEK_SET);

    const array = corpse.readBytes(4);
    const bytes = new Uint8Array(array);
    const magic =
      ((bytes[0] as number) << 24) |
      ((bytes[1] as number) << 16) |
      ((bytes[2] as number) << 8) |
      (bytes[3] as number);

    if (magic === CorpseCmdLet.MAGIC) {
      Output.writeln(`Magic is [${Output.green('OK')}]`);
    } else {
      Output.writeln(`Magic is [${Output.red('BAD')}]`);
    }
  }

  public usage(): Var {
    Output.writeln(CorpseCmdLet.USAGE);
    return Var.ZERO;
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'linux':
        this.pGetrlimit = Module.findExportByName(null, 'getrlimit');
        this.pSetrlimit = Module.findExportByName(null, 'setrlimit');
        this.pFork = Module.findExportByName(null, 'fork');
        this.pWaitPid = Module.findExportByName(null, 'waitpid');
        this.pGetPid = Module.findExportByName(null, 'getpid');
        this.pKill = Module.findExportByName(null, 'kill');
        if (
          this.pGetrlimit === null ||
          this.pSetrlimit === null ||
          this.pFork === null ||
          this.pWaitPid === null ||
          this.pGetPid === null ||
          this.pKill === null
        )
          return false;
        break;
      case 'darwin':
      case 'freebsd':
      case 'qnx':
      case 'windows':
      case 'barebone':
      default:
        return false;
    }

    return true;
  }
}
