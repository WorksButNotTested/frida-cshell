import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Regs } from '../breakpoints/regs.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Format } from '../misc/format.js';

const USAGE: string = `Usage: bt
bt - show the backtrace for the current thread in a breakpoint

bt name - show backtrace for thread
  thread   the name of the thread to show backtrace for
`;

export class BtCmdLet extends CmdLet {
  name = 'bt';
  category = 'thread';
  help = 'display backtrace information';

  public runSync(tokens: Token[]): Var {
    const retWithId = this.runShowId(tokens);
    if (retWithId !== null) return retWithId;

    const retWithName = this.runShowNamed(tokens);
    if (retWithName !== null) return retWithName;

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
        this.printBacktrace(t.context);
      });
      return new Var(uint64(id), `Thread: ${id}`);
    }
  }

  private printBacktrace(ctx: CpuContext) {
    Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .forEach(s => {
        const prefix = s.moduleName === null ? '' : `${s.moduleName}!`;
        const name = `${prefix}${s.name}`;
        Output.write(
          `${Output.green(name.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(s.address))}`,
        );
        if (s.fileName !== null && s.lineNumber !== null) {
          if (s.fileName.length !== 0 && s.lineNumber !== 0) {
            Output.write(
              `\t${Output.blue(s.fileName)}:${Output.blue(s.lineNumber.toString())} `,
            );
          }
        }
        Output.writeln();
      });
  }

  private runShowNamed(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return null;
    const [[], [name]] = vars as [[], [string | null]];

    if (name === null) {
      const ctx = Regs.getContext();
      if (ctx === null)
        throw new Error(
          `backtrace requires context, only available in breakpoints`,
        );

      this.printBacktrace(ctx);
      return Var.ZERO;
    } else {
      const matches = Process.enumerateThreads().filter(t => t.name === name);
      switch (matches.length) {
        case 0:
          Output.writeln(`Thread: ${name} not found`);
          return Var.ZERO;
        case 1: {
          const t = matches[0] as ThreadDetails;
          this.printBacktrace(t.context);
          return new Var(uint64(t.id), `Thread: ${t.id}`);
        }
        default:
          matches.forEach(t => {
            this.printBacktrace(t.context);
          });
          return Var.ZERO;
      }
    }
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
