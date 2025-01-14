import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Regs } from '../../breakpoints/regs.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { BacktraceType, Exception } from '../../misc/exception.js';

export class BtCmdLet extends CmdLetBase {
  name = 'bt';
  category = 'thread';
  help = 'display backtrace information';

  private static readonly USAGE: string = `Usage: bt
bt [type] - show the backtrace for the current thread in a breakpoint
  type   the type of backtrace to show [fuzzy | accurate (default)]

bt id [type] - show backtrace for thread
  id     the id of the thread to show backtrace for
  type   the type of backtrace to show [fuzzy | accurate (default)]

bt name - show backtrace for thread
  name   the name of the thread to show backtrace for
  type   the type of backtrace to show [fuzzy | accurate (default)]`;

  public runSync(tokens: Token[]): Var {
    const retCurrent = this.runShowCurrent(tokens);
    if (retCurrent !== null) return retCurrent;

    const retWithId = this.runShowId(tokens);
    if (retWithId !== null) return retWithId;

    const retWithName = this.runShowNamed(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private runShowCurrent(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseType]);
    if (vars === null) return null;
    const [_, [type]] = vars as [[], [BacktraceType | undefined | null]];

    /*
     * What we think is a backtrace type might actually be a thread name
     * or id.
     */
    if (type === undefined) return null;

    const ctx = Regs.getContext();
    if (ctx === null)
      throw new Error(
        `backtrace requires context, only available in breakpoints`,
      );

    Exception.printBacktrace(ctx, type ?? BacktraceType.Accurate);
    return Var.ZERO;
  }

  private runShowId(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar],
      [this.parseType],
    );
    if (vars === null) return null;
    const [[v0], [type]] = vars as [[Var], [BacktraceType | undefined | null]];
    const id = v0.toU64().toNumber();
    if (type === undefined) throw new Error('invalid backtrace type');

    const matches = Process.enumerateThreads().filter(t => t.id === id);
    if (matches.length === 0) {
      Output.writeln(`Thread #${id} not found`);
      return Var.ZERO;
    } else {
      matches.forEach(t => {
        Exception.printBacktrace(t.context, type ?? BacktraceType.Accurate);
      });
      return new Var(uint64(id), `Thread: ${id}`);
    }
  }

  private runShowNamed(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseLiteral],
      [this.parseType],
    );
    if (vars === null) return null;
    const [[name], [type]] = vars as [
      [string],
      [BacktraceType | undefined | null],
    ];
    if (type === undefined) throw new Error('invalid backtrace type');

    const matches = Process.enumerateThreads().filter(t => t.name === name);
    switch (matches.length) {
      case 0:
        Output.writeln(`Thread: ${name} not found`);
        return Var.ZERO;
      case 1: {
        const t = matches[0] as ThreadDetails;
        Exception.printBacktrace(t.context, type ?? BacktraceType.Accurate);
        return new Var(uint64(t.id), `Thread: ${t.id}`);
      }
      default:
        matches.forEach(t => {
          Exception.printBacktrace(t.context, type ?? BacktraceType.Accurate);
        });
        return Var.ZERO;
    }
  }

  protected parseType(token: Token): BacktraceType | undefined {
    if (token === null) return BacktraceType.Accurate;
    const literal = token.getLiteral();
    switch (literal) {
      case 'fuzzy':
        return BacktraceType.Fuzzy;
      case 'accurate':
        return BacktraceType.Accurate;
      default:
        return undefined;
    }
  }

  public usage(): Var {
    Output.writeln(BtCmdLet.USAGE);
    return Var.ZERO;
  }
}
