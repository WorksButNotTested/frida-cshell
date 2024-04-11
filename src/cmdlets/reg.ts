import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Vars } from '../vars.js';
import { Token } from '../token.js';
import { Var } from '../var.js';
import { Regs } from '../regs.js';

const USAGE: string = `Usage: r
r - show the values of all registers

r name - display the value of a named register
  name    the name of the register to display

v name value - assign a value to a register
  name    the name of the register to assign
  value   the value to assign
`;

export class RegCmdLet extends CmdLet {
  name = 'r';
  category = 'breakpoints';
  help = 'register management';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private runWithNameAndPointer(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const value = tokens[1]?.toVar();
    if (value === undefined) return undefined;

    Regs.set(name, value);
    return value;
  }

  private runWithName(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const val = Regs.get(name);
    Output.writeln(`Register ${name}, value: ${val.toString()}`);
    return val;
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Output.writeln('Regs:');
    for (const [key, value] of Regs.all()) {
      Output.writeln(`${key.padEnd(25, ' ')}: ${value.toString()}`);
    }
    return Vars.getRet();
  }

  public run(tokens: Token[]): Var {
    const retWithNameAndPointer = this.runWithNameAndPointer(tokens);
    if (retWithNameAndPointer !== undefined) return retWithNameAndPointer;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }
}
