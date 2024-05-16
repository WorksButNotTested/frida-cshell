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

  private runWithId(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const id = v0.toU64().toNumber();
    if (id === null) return null;

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

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();

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

  private runWithoutParams(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    const ctx = Regs.getContext();
    if (ctx === null)
      throw new Error(
        `backtrace requires context, only available in breakpoints`,
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
    if (retWithId !== null) return retWithId;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== null) return retWithoutParams;

    return this.usage();
  }
}
