import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Vars } from '../vars/vars.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Regs } from '../breakpoints/regs.js';

const USAGE: string = `Usage: R
R - show the values of all registers

R name - display the value of a named register
  name    the name of the register to display

R name value - assign a value to a register
  name    the name of the register to assign
  value   the value to assign
`;

export class RegCmdLet extends CmdLet {
  name = 'R';
  category = 'breakpoints';
  help = 'register management';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private runWithNameAndPointer(tokens: Token[]): Var | null {
    if (tokens.length !== 2) return null;

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];

    const name = t0.getLiteral();

    const value = t1.toVar();
    if (value === null) return null;

    Regs.set(name, value);
    Output.writeln(`Register ${name}, set to value: ${value.toString()}`);
    return value;
  }

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();
    if (name === null) return null;

    const val = Regs.get(name);
    Output.writeln(`Register ${name}, value: ${val.toString()}`);
    return val;
  }

  private runWithoutParams(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    Output.writeln('Registers:');
    for (const [key, value] of Regs.all()) {
      Output.writeln(`${Output.bold(key.padEnd(4, ' '))}: ${value.toString()}`);
    }
    return Vars.getRet();
  }

  public run(tokens: Token[]): Var {
    const retWithNameAndPointer = this.runWithNameAndPointer(tokens);
    if (retWithNameAndPointer !== null) return retWithNameAndPointer;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== null) return retWithoutParams;

    return this.usage();
  }
}
