import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Vars } from '../../vars/vars.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class VarCmdLet extends CmdLet {
  name = 'v';
  category = 'misc';
  help = 'variable management';

  private static readonly USAGE: string = `Usage: v
v - show the values of all variables

v name - display the value of a named variable
  name    the name of the variable to display

v name value - assign a value to a variable
  name    the name of the variable to assign
  value   the value to assign

v name ${CmdLet.DELETE_CHAR} - delete a variable
  name    the name of the variable to delete`;

  public runSync(tokens: Token[]): Var {
    const retWithNameAndHash = this.runDelete(tokens);
    if (retWithNameAndHash !== null) return retWithNameAndHash;

    const retWithNameAndPointer = this.runSet(tokens);
    if (retWithNameAndPointer !== null) return retWithNameAndPointer;

    const retWithName = this.runShow(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private runDelete(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseLiteral, this.parseDelete]);
    if (vars === null) return null;
    const [name, _] = vars as [string, string];

    const val = Vars.delete(name);
    if (val === null) {
      Output.writeln(`Variable ${name} not assigned`);
      return Var.ZERO;
    } else {
      return val;
    }
  }

  private runSet(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseLiteral, this.parseVar]);
    if (vars === null) return null;
    const [name, value] = vars as [string, Var];
    Vars.set(name, value);
    return value;
  }

  private runShow(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return null;
    const [_, [name]] = vars as [[], [string | null]];

    if (name === null) {
      Output.writeln('Vars:');
      for (const [key, value] of Vars.all()) {
        Output.writeln(
          [
            `${Output.green(key.padEnd(25, ' '))}:`,
            `${Output.yellow(value.toString())}`,
          ].join(' '),
          true,
        );
      }
      return Vars.getRet();
    } else {
      const val = Vars.get(name);
      if (val === null) {
        Output.writeln(`Variable ${Output.green(name)} not assigned`);
        return Var.ZERO;
      } else {
        Output.writeln(
          [
            `Variable ${Output.green(name)}`,
            `value: ${Output.yellow(val.toString())}`,
          ].join(' '),
        );
        return val;
      }
    }
  }

  public usage(): Var {
    Output.writeln(VarCmdLet.USAGE);
    return Var.ZERO;
  }
}
