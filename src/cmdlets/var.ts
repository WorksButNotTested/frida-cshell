import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Vars } from '../vars/vars.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const DELETE_CHAR: string = '#';

const USAGE: string = `Usage: v
v - show the values of all variables

v name - display the value of a named variable
  name    the name of the variable to display

v name value - assign a value to a variable
  name    the name of the variable to assign
  value   the value to assign

v name ${DELETE_CHAR} - delete a variable
  name    the name of the variable to delete
`;

export class VarCmdLet extends CmdLet {
  name = 'v';
  category = 'misc';
  help = 'variable management';

  public runSync(tokens: Token[]): Var {
    const retWithNameAndHash = this.runWithNameAndHash(tokens);
    if (retWithNameAndHash !== null) return retWithNameAndHash;

    const retWithNameAndPointer = this.runWithNameAndPointer(tokens);
    if (retWithNameAndPointer !== null) return retWithNameAndPointer;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== null) return retWithoutParams;

    return this.usage();
  }

  private runWithNameAndHash(tokens: Token[]): Var | null {
    if (tokens.length !== 2) return null;

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];

    const name = t0.getLiteral();
    const value = t1.getLiteral();
    if (value !== DELETE_CHAR) return null;

    const val = Vars.delete(name);
    if (val === null) {
      Output.writeln(`Variable ${name} not assigned`);
      return Var.ZERO;
    } else {
      return val;
    }
  }

  private runWithNameAndPointer(tokens: Token[]): Var | null {
    if (tokens.length !== 2) return null;

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];

    const name = t0.getLiteral();

    const value = t1.toVar();
    if (value === null) return null;

    Vars.set(name, value);
    return value;
  }

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();

    const val = Vars.get(name);
    if (val === null) {
      Output.writeln(`Variable ${name} not assigned`);
      return Var.ZERO;
    } else {
      Output.writeln(`Varaible ${name}, value: ${val.toString()}`);
      return val;
    }
  }

  private runWithoutParams(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    Output.writeln('Vars:');
    for (const [key, value] of Vars.all()) {
      Output.writeln(`${key.padEnd(25, ' ')}: ${value.toString()}`);
    }
    return Vars.getRet();
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
