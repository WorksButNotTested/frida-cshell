import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Vars } from '../../vars/vars.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Regs } from '../../breakpoints/regs.js';

export class RegCmdLet extends CmdLet {
  name = 'R';
  category = 'breakpoints';
  help = 'register management';

  private static readonly USAGE: string = `Usage: R
R - show the values of all registers

R name - display the value of a named register
  name    the name of the register to display

R name value - assign a value to a register
  name    the name of the register to assign
  value   the value to assign`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(
      tokens,
      [],
      [this.parseRegister, this.parseVar],
    );
    if (vars === null) return this.usage();
    const [_, [name, address]] = vars as [[], [string | null, Var | null]];

    if (address === null) {
      if (name === null) {
        Output.writeln('Registers:');
        for (const [key, value] of Regs.all()) {
          Output.writeln(
            `${Output.bold(key.padEnd(4, ' '))}: ${value.toString()}`,
            true,
          );
        }
        return Vars.getRet();
      } else {
        const val = Regs.get(name);
        Output.writeln(`Register ${name}, value: ${val.toString()}`);
        return val;
      }
    } else {
      if (name === null) throw new Error('argument parsing error');
      Regs.set(name, address);
      Output.writeln(`Register ${name}, set to value: ${address.toString()}`);
      return address;
    }
  }

  protected parseRegister(token: Token): string | null {
    if (token === null) return null;
    const literal = token.getLiteral();
    if (literal.startsWith('$')) {
      return literal.slice(1);
    } else {
      return literal;
    }
  }

  public usage(): Var {
    Output.writeln(RegCmdLet.USAGE);
    return Var.ZERO;
  }
}
