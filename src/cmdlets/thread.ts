import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Token } from '../token.js';
import { Var } from '../var.js';

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
        this.printThread(t);
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

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) {
      return undefined;
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
    if (retWithId !== undefined) return retWithId;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }
}
