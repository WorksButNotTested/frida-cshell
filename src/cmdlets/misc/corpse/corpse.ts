import { CmdLetBase } from '../../../commands/cmdlet.js';
import { Output } from '../../../io/output.js';
import { Token } from '../../../io/token.js';
import { Exception } from '../../../misc/exception.js';
import { Files } from '../../../misc/files.js';
import { Format } from '../../../misc/format.js';
import { Var } from '../../../vars/var.js';
import { Clone } from './clone.js';
import { CoreFilter } from './core_filter.js';
import { CorePattern } from './core_pattern.js';
import { Dumpable } from './dumpable.js';
import { Proc } from './proc.js';
import { Rlimit } from './rlimit.js';
import { SeLinux } from './selinux.js';

export class CorpseCmdLet extends CmdLetBase {
  name = 'corpse';
  category = 'misc';
  help = 'create a corpse file';

  private static readonly USAGE: string = `Usage: corpse
corpse - create a corpse file`;

  private static readonly CHILD_SLEEP_DURATION: number = 0.1;
  private static readonly PARENT_SLEEP_DURATION: number = 0.5;
  private static readonly WAIT_DURATION: number = 20;
  private static readonly PARENT_DELAY_DURATION: number = 2;
  private static readonly ELF_MAGIC: number = 0x7f454c46;

  private rlimit: Rlimit | null = null;
  private dumpable: Dumpable | null = null;
  private clone: Clone | null = null;
  private proc: Proc | null = null;

  public runSync(tokens: Token[]): Var {
    if (tokens.length != 0) {
      Output.writeln(CorpseCmdLet.USAGE);
      return Var.ZERO;
    }

    const corePattern = CorePattern.get();
    this.status(`Got core pattern: '${corePattern}'`);

    if (SeLinux.isPermissive()) {
      this.status(`SELinux is in permissive mode`);
    } else {
      this.warning(`SELinux may NOT be in permissive mode:
        run 'setenforce 0' to disable`);
    }

    /* set the rlimit */
    const rlimit = this.rlimit as Rlimit;
    const limit = rlimit.get();
    this.debug(
      `Read rlimit - soft: ${limit.sortLimit}, hard: ${limit.hardLimit}`,
    );
    if (rlimit.isUnlimited(limit)) {
      this.debug('Rlimit is unlimited');
    } else {
      this.debug('Setting rlimit to unlimited');
      rlimit.set(Rlimit.UNLIMITED);
    }
    this.status('Rlimit has been configured');

    try {
      /* Set the core filter*/
      const coreFilter = CoreFilter.get();
      this.status(`Read core filter: 0x${coreFilter.toString(16)}`);
      if (coreFilter.equals(CoreFilter.NEEDED)) {
        this.debug('Core filter is already set');
      } else {
        this.debug('Setting core filter');
        CoreFilter.trySet(CoreFilter.NEEDED);
      }
      this.status('Core filter has been configured');

      try {
        /* set dumpable */
        const dumpable = this.dumpable as Dumpable;
        const isDumpable = dumpable.get();
        this.status(`Read dumpable: ${isDumpable}`);
        if (isDumpable === 0) {
          this.debug('Setting dumpable');
          dumpable.set(1);
        } else {
          this.debug('Dumpable is already set');
        }
        this.status('Dumpable has been configured');

        /* run the clone */
        try {
          const debugFileName = Files.getRandomFileName('debug');
          this.status(`Creating debug file: '${debugFileName}'`);
          const debugFile = new File(debugFileName, 'w');
          const debug = (msg: string) => {
            debugFile.write(`${msg}\n`);
            debugFile.flush();
          };

          this.status('Reconfiguring exception handling');
          Exception.propagate();
          try {
            const clone = this.clone as Clone;
            const childPid = clone.clone(
              (childPid: number) => {
                this.runParent(childPid);
              },
              () => {
                this.runChild(debug);
              },
            );
            this.debug(
              `Checking for corpse - core pattern: '${corePattern}', pid: ${childPid}`,
            );
            this.checkCorpse(corePattern, childPid);
          } finally {
            this.status('Restoring exception handling');
            Exception.suppress();
            this.debug(`Checking debug file: '${debugFileName}'`);
            this.checkDebugFile(debugFileName);
          }
        } finally {
          /* Restore dumpable */
          this.status('Restoring dumpable');
          if (isDumpable === 0) {
            this.debug('Resetting dumpable');
            dumpable.set(isDumpable);
          } else {
            this.debug('No need to reset dumpable');
          }
          this.debug('Restored dumpable');
        }
      } finally {
        /* Restore core filter */
        this.status('Restoring core filter');
        if (coreFilter.equals(CoreFilter.NEEDED)) {
          this.debug('No need to restore core filter');
        } else {
          this.debug('Restoring core filter');
          CoreFilter.trySet(coreFilter);
        }
        this.debug('Restored core filter');
      }
    } finally {
      /* Restore rlimit */
      this.status('Restoring rlimit');
      if (rlimit.isUnlimited(limit)) {
        this.debug('No need to restore rlimit');
      } else {
        this.debug('Restoring rlimit');
        rlimit.set(limit);
      }
      this.debug('Restored rlimit');
    }

    return Var.ZERO;
  }

  private runParent(childPid: number) {
    this.debug(`Running parent, pid: ${Process.id}, child pid: ${childPid}`);

    const proc = this.proc as Proc;

    this.debug(`Delaying: ${CorpseCmdLet.PARENT_DELAY_DURATION}s`);
    Thread.sleep(CorpseCmdLet.PARENT_DELAY_DURATION);

    const limit =
      CorpseCmdLet.WAIT_DURATION / CorpseCmdLet.PARENT_SLEEP_DURATION;

    this.debug(`Parent limit: ${limit}`);
    this.debug(`Delay between signals: ${CorpseCmdLet.PARENT_SLEEP_DURATION}s`);
    for (let i = 0; i < limit; i++) {
      proc.kill(childPid, Proc.SIGABRT);

      const status = proc.waitpid(childPid);
      this.debug(
        [
          `index: ${i},`,
          `exitStatus: ${status.exitStatus},`,
          `termSignal: ${status.termSignal},`,
          `stopped: ${status.stopped}`,
        ].join(' '),
      );

      if (status.stopped) return;
      Thread.sleep(CorpseCmdLet.PARENT_SLEEP_DURATION);
    }
    this.status(`Child not stopped, pid: ${childPid}`);
    proc.kill(childPid, Proc.SIGKILL);
    throw new Error(`Child not stopped, pid: ${childPid}`);
  }

  private runChild(debug: (msg: string) => void) {
    debug(`Running child`);
    const proc = this.proc as Proc;
    const pid = proc.getpid();
    debug(`PID: ${pid}`);

    try {
      const limit =
        CorpseCmdLet.WAIT_DURATION / CorpseCmdLet.CHILD_SLEEP_DURATION;
      debug(`Child limit: ${limit}`);
      debug(`Delay between sleeps: ${CorpseCmdLet.CHILD_SLEEP_DURATION}s`);
      for (let i = 0; i < limit; i++) {
        Thread.sleep(CorpseCmdLet.CHILD_SLEEP_DURATION);
      }
      debug(`Child limit exceeded`);
    } catch (error) {
      if (error instanceof Error) {
        debug(`ERROR: ${error.message}`);
        debug(`STACK: ${error.stack}`);
      } else {
        debug(`UNKNOWN ERROR: ${error}`);
      }
    } finally {
      debug(`Suicide`);
      proc.kill(pid, Proc.SIGKILL);
    }
  }

  private checkCorpse(corePattern: string, pid: number) {
    const corePath = CorePattern.appendPid()
      ? `${corePattern}.${pid}`
      : corePattern;
    this.status(`Checking for corpse at '${corePath}'`);

    const corpse = new File(corePath, 'rb');
    corpse.seek(0, File.SEEK_END);
    const length = corpse.tell();
    corpse.seek(0, File.SEEK_SET);

    this.status(`Corpse is ${Format.toSize(length)}`);

    const array = corpse.readBytes(4);
    const bytes = new Uint8Array(array);
    const magic =
      ((bytes[0] as number) << 24) |
      ((bytes[1] as number) << 16) |
      ((bytes[2] as number) << 8) |
      (bytes[3] as number);

    if (magic === CorpseCmdLet.ELF_MAGIC) {
      this.status(`Magic is [${Output.green('OK')}]`);
    } else {
      this.status(`Magic is [${Output.red('BAD')}]`);
    }
  }

  private checkDebugFile(debugFileName: string) {
    const debugFile = new File(debugFileName, 'r');
    this.debug('Child output...');
    for (
      let line = debugFile.readLine();
      line.length != 0;
      line = debugFile.readLine()
    ) {
      this.debug(`\t${Output.yellow(line.trimEnd())}`);
    }

    this.debug('Child output complete');
  }

  private status(msg: string) {
    Output.writeln(`[${Output.green('*')}] ${msg}`);
  }

  private debug(msg: string) {
    Output.debug(`[${Output.blue('*')}] ${msg}`);
  }

  private warning(msg: string) {
    Output.writeln(`[${Output.red('*')}] ${msg}`);
  }

  public usage(): Var {
    Output.writeln(CorpseCmdLet.USAGE);
    return Var.ZERO;
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'linux':
        try {
          this.rlimit = new Rlimit();
          this.dumpable = new Dumpable();
          this.clone = new Clone();
          this.proc = new Proc();
        } catch {
          return false;
        }
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
