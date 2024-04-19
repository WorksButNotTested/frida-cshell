import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Regs } from '../breakpoints/regs.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: bt
bt - show the backtrace for the current thread in a breakpoint

bt name - show backtrace for thread
  thread   the name of the thread to show backtrace for
`;

export class BtCmdLet extends CmdLet {
  name = 'bt';
  category = 'thread';
  help = 'display backtrace information';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private printBacktrace(t: ThreadDetails) {
    Output.writeln(
      Thread.backtrace(t.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join('\n'),
    );
  }

  private runWithId(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const id = tokens[0]?.toVar()?.toU64().toNumber();
    if (id === undefined) return undefined;

    const matches = Process.enumerateThreads().filter(t => t.id === id);
    if (matches.length === 0) {
      Output.writeln(`Thread #${id} not found`);
      return Var.ZERO;
    } else {
      matches.forEach(t => {
        this.printBacktrace(t);
      });
      return new Var(uint64(id));
    }
  }

  private runWithName(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const matches = Process.enumerateThreads().filter(t => t.name === name);
    switch (matches.length) {
      case 0:
        Output.writeln(`Thread: ${name} not found`);
        return Var.ZERO;
      case 1: {
        const t = matches[0] as ThreadDetails;
        this.printBacktrace(t);
        return new Var(uint64(t.id));
      }
      default:
        matches.forEach(t => {
          this.printBacktrace(t);
        });
        return Var.ZERO;
    }
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length != 0) return undefined;

    const ctx = Regs.getContext();
    if (ctx === null)
      throw new Error(
        `Backtrace requires context, only available in breakpoints`,
      );

    Output.writeln(
      Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join('\n'),
    );
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithId = this.runWithId(tokens);
    if (retWithId !== undefined) return retWithId;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }
}
