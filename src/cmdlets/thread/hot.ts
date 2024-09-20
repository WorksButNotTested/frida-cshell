import { Numeric } from '../../misc/numeric.js';
import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Format } from '../../misc/format.js';
import { Input } from '../../io/input.js';

export class HotCmdLet extends CmdLet {
  name = 'hot';
  category = 'thread';
  help = 'display thread execution time information';

  private static readonly MAX_DURATION: number = 10;
  private static readonly USAGE: string = `Usage: t

hot * - show execution time for all threads

hot * duration - show execution time for all threads during a given time period
  duration   the duration in seconds (maximum of ${HotCmdLet.MAX_DURATION}) over which to time the threads

hot id - show execution time for given thread
  id    the id of the thread to show information for

hot id duration - show execution time for given thread during a given time period
  id         the id of the thread to show information for
  duration   the duration in seconds (maximum of ${HotCmdLet.MAX_DURATION}) over which to time the thread

hot name - show execution time for given thread
  name  the name of the thread to show information for

hot name duration - show execution time for given thread during a given time period
  name       the name of the thread to show information for
  duration   the duration in seconds (maximum of ${HotCmdLet.MAX_DURATION}) over which to time the thread`;

  private static readonly FIELD_NAMES = [
    'pid',
    'comm',
    'state',
    'ppid',
    'pgrp',
    'session',
    'tty_nr',
    'tpgid',
    'flags',
    'minflt',
    'cminflt',
    'majflt',
    'cmajflt',
    'utime',
    'stime',
    'cutime',
    'cstime',
    'priority',
    'nice',
    'num_threads',
    'itrealvalue',
    'starttime',
    'vsize',
    'rss',
    'rsslim',
    'startcode',
    'endcode',
    'startstack',
    'kstkesp',
    'kstkeip',
    'signal',
    'blocked',
    'sigignore',
    'sigcatch',
    'wchan',
    'nswap',
    'cnswap',
    'exit_signal',
    'processor',
    'rt_priority',
    'policy',
    'delayacct_blkio_ticks',
    'guest_time',
    'cguest_time',
    'start_data',
    'end_data',
    'start_brk',
    'arg_start',
    'arg_end',
    'env_start',
    'env_end',
    'exit_code',
  ];

  private static readonly _SC_CLK_TCK: number = 2;
  private pSysConf: NativePointer | null = null;
  private ticksPerSecond: UInt64 | null = null;

  public runSync(tokens: Token[]): Var {
    if (this.ticksPerSecond === null) {
      this.ticksPerSecond = this.getTicksPerSecond();
    }

    if (this.ticksPerSecond === null) {
      throw Error('failed to get ticks per second');
    }

    const retWithId = this.runShowId(tokens);
    if (retWithId !== null) return retWithId;

    const retWithName = this.runShowName(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private getTicksPerSecond(): UInt64 | null {
    if (this.pSysConf === null) return null;
    const sysConf = new NativeFunction(this.pSysConf, 'pointer', ['int']);
    const ret = sysConf(HotCmdLet._SC_CLK_TCK);
    const val = uint64(ret.toString());
    if (val === uint64('0xffffffffffffffff')) return null;
    return val;
  }

  private runShowId(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseNumberOrAll],
      [this.parseDuration],
    );
    if (vars === null) return null;
    const [[id], [duration]] = vars as [[number], [number | null]];

    Output.debug(`id: ${id}`);

    const matches = Process.enumerateThreads().filter(
      t => id === -1 || t.id === id,
    );
    const search = id === -1 ? null : `#${id}`;
    return this.printThreads(matches, duration, search);
  }

  private runShowName(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseLiteral],
      [this.parseDuration],
    );
    if (vars === null) return null;
    const [[name], [duration]] = vars as [[string], [number | null]];

    const matches = Process.enumerateThreads().filter(t => t.name === name);
    return this.printThreads(matches, duration, name);
  }

  private parseDuration(token: Token): number | null {
    const v = token.toVar();
    if (v === null) return null;
    const num = v.toU64().toNumber();
    if (num > HotCmdLet.MAX_DURATION) return null;
    return num;
  }

  private printThreads(
    threads: ThreadDetails[],
    duration: number | null,
    search: string | null = null,
  ): Var {
    if (threads.length !== 0) {
      if (duration === null) {
        const startTimes = threads.reduce<Record<ThreadId, UInt64>>(
          (times, t, _index) => {
            times[t.id] = uint64('0');
            return times;
          },
          {},
        );
        const endTimes = this.getThreadTimes(threads);
        this.printThreadTimes(threads, startTimes, endTimes);
      } else {
        Output.writeln(`Statictics will be displayed in ${duration} seconds`);
        const startTimes = this.getThreadTimes(threads);
        setTimeout(() => {
          const endTimes = this.getThreadTimes(threads);
          Output.clearLine();
          Output.writeln(Output.yellow('-'.repeat(80)));
          Output.writeln(
            `${Output.yellow('|')} Displaying hot thread statistics:`,
          );
          Output.writeln(Output.yellow('-'.repeat(80)));
          Input.suppressIntercept(true);
          Output.setIndent(true);
          Output.writeln();
          try {
            this.printThreadTimes(threads, startTimes, endTimes);
            Output.writeln();
          } finally {
            Output.setIndent(false);
            Input.suppressIntercept(false);
            Output.writeln(Output.yellow('-'.repeat(80)));
            Input.prompt();
          }
        }, duration * 1000);
      }
    }

    switch (threads.length) {
      case 0:
        if (search === null) {
          Output.writeln('No threads found');
        } else {
          Output.writeln(`Thread: ${search} not found`);
        }
        return Var.ZERO;
      case 1: {
        const t = threads[0] as ThreadDetails;
        return new Var(uint64(t.id), `Thread: ${t.id}`);
      }
      default:
        return Var.ZERO;
    }
  }

  private getThreadTimes(
    threads: ThreadDetails[],
  ): Record<ThreadId, UInt64 | null> {
    const result = threads.reduce<Record<ThreadId, UInt64 | null>>(
      (times, t, _index) => {
        try {
          const path = `/proc/${Process.id}/task/${t.id}/stat`;
          Output.debug(`path: ${path}`);
          const data = File.readAllText(path);
          Output.debug(`data: ${data}`);
          const fields = data.split(' ');
          const stats: Record<string, string | undefined> =
            HotCmdLet.FIELD_NAMES.reduce<Record<string, string | undefined>>(
              (acc, key, index) => {
                acc[key] = fields[index];
                return acc;
              },
              {},
            );

          Object.keys(stats).forEach((key, index) => {
            const val = stats[key];
            const valString =
              val === undefined ? Output.red('undefined') : Output.yellow(val);
            Output.debug(
              [
                `${Output.green(index.toString().padStart(3, ' '))}.`,
                `${Output.blue(key)}:`,
                `${valString}`,
              ].join(' '),
            );
          });

          const val = stats['utime'] ?? null;
          const utime = val == null ? null : Numeric.parse(val);
          times[t.id] = utime;
        } catch {
          times[t.id] = null;
        }
        return times;
      },
      {},
    );

    return result;
  }

  private printThreadTimes(
    threads: ThreadDetails[],
    startTimes: Record<ThreadId, UInt64 | null>,
    endTimes: Record<ThreadId, UInt64 | null>,
  ) {
    const ticks = this.ticksPerSecond;
    if (ticks === null) {
      throw Error('failed to get ticks per second');
    }

    const deltas = threads.reduce<Record<ThreadId, UInt64 | null>>(
      (acc, t, _index) => {
        const startTime = startTimes[t.id] as UInt64 | null;
        const endTime = endTimes[t.id] as UInt64 | null;
        if (startTime === null) {
          acc[t.id] = null;
        } else if (endTime === null) {
          acc[t.id] = null;
        } else {
          const delta = endTime.sub(startTime);
          acc[t.id] = delta;
        }
        return acc;
      },
      {},
    );

    const sorted = threads
      .map(t => {
        return { thread: t, time: deltas[t.id] as UInt64 | null };
      })
      .sort((a, b) => {
        if (a.time === null) {
          return 1;
        } else if (b.time === null) {
          return -1;
        } else {
          return b.time.compare(a.time);
        }
      });

    sorted.forEach(t => {
      let timeString = Output.red('unknown');
      if (t.time !== null) {
        const millis = (t.time.toNumber() * 1000) / ticks.toNumber();
        timeString = `${Output.yellow(Format.toDecString(millis))} ms`;
      }

      Output.writeln(
        [
          `${Output.yellow(t.thread.id.toString().padStart(5, ' '))}:`,
          `${Output.green((t.thread.name ?? '[UNNAMED]').padEnd(15, ' '))}`,
          `[state: ${Output.blue(t.thread.state)}]`,
          `[time: ${timeString}]`,
        ].join(' '),
        threads.length > 1,
      );
    });
  }

  public usage(): Var {
    Output.writeln(HotCmdLet.USAGE);
    return Var.ZERO;
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'linux':
        this.pSysConf = Module.findExportByName(null, 'sysconf');
        return true;
      case 'windows':
      case 'barebone':
      default:
        return false;
    }
  }
}
