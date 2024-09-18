import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: t

t - show all threads

t name - show named thread
  name  the name of the thread to show information for`;

export class ThreadCmdLet extends CmdLet {
  name = 't';
  category = 'thread';
  help = 'display thread information';

  public runSync(tokens: Token[]): Var {
    const retWithId = this.runShowId(tokens);
    if (retWithId !== null) return retWithId;

    const retWithName = this.runShowName(tokens);
    if (retWithName !== null) return retWithName;

    const retWithoutParams = this.runShowAll(tokens);
    if (retWithoutParams !== null) return retWithoutParams;

    return this.usage();
  }

  private runShowId(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return null;
    const [v0] = vars as [Var];

    const id = v0.toU64().toNumber();

    const matches = Process.enumerateThreads().filter(t => t.id === id);
    if (matches.length === 0) {
      Output.writeln(`Thread #${id} not found`);
      return Var.ZERO;
    } else {
      matches.forEach(t => {
        this.printThread(t);
      });
      return new Var(uint64(id), `Thread: ${id}`);
    }
  }

  private printThread(t: ThreadDetails, filtered: boolean = true) {
    Output.writeln(
      [
        `${Output.yellow(t.id.toString().padStart(5, ' '))}:`,
        `${Output.green((t.name ?? '[UNNAMED]').padEnd(15, ' '))}`,
        `${Output.blue(t.state)}`,
        `pc: ${Output.yellow(Format.toHexString(t.context.pc))}`,
        `sp: ${Output.yellow(Format.toHexString(t.context.sp))}`,
      ].join(' '),
      filtered,
    );
  }

  private runShowName(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseLiteral]);
    if (vars === null) return null;
    const [name] = vars as [string];

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
          this.printThread(t, true);
        });
        return Var.ZERO;
    }
  }

  private runShowAll(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    const threads = Process.enumerateThreads();
    switch (threads.length) {
      case 0:
        Output.writeln('No threads found');
        return Var.ZERO;
      case 1: {
        const t = threads[0] as ThreadDetails;
        this.printThread(t);
        return new Var(uint64(t.id), `Thread: ${t.id}`);
      }
      default:
        threads.forEach(t => {
          this.printThread(t, true);
        });
        return Var.ZERO;
    }
  }

  public usage(): Var {
    Output.writeln(USAGE);
    return Var.ZERO;
  }
}
