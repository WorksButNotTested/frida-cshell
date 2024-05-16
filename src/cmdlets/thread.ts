import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: t

t - show all threads

t name - show named thread
  name  the name of the thread to show information for
`;

export class ThreadCmdLet extends CmdLet {
  name = 't';
  category = 'thread';
  help = 'display thread information';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private printThread(t: ThreadDetails) {
    Output.writeln(
      `${t.id.toString().padStart(5, ' ')}: ${(t.name ?? '[UNNAMED]').padEnd(15, ' ')} ${t.state} pc: ${t.context.pc} sp: ${t.context.sp}`,
    );
  }

  private runWithId(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const id = v0.toU64().toNumber();

    const matches = Process.enumerateThreads().filter(t => t.id === id);
    if (matches.length === 0) {
      Output.writeln(`Thread #${id} not found`);
      return Var.ZERO;
    } else {
      matches.forEach(t => {
        this.printThread(t);
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
        this.printThread(t);
        return new Var(uint64(t.id));
      }
      default:
        matches.forEach(t => {
          this.printThread(t);
        });
        return Var.ZERO;
    }
  }

  private runWithoutParams(tokens: Token[]): Var | null {
    if (tokens.length !== 0) {
      return null;
    }

    const threads = Process.enumerateThreads();
    switch (threads.length) {
      case 0:
        Output.writeln('No threads found');
        return Var.ZERO;
      case 1: {
        const t = threads[0] as ThreadDetails;
        this.printThread(t);
        return new Var(uint64(t.id));
      }
      default:
        threads.forEach(t => {
          this.printThread(t);
        });
        return Var.ZERO;
    }
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
