import { CmdLet } from '../../commands/cmdlet.js';
import { Command } from '../../commands/command.js';
import { Input, InputInterceptLine } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Parser } from '../../io/parser.js';
import { Token } from '../../io/token.js';
import { Macro, Macros } from '../../macros/macros.js';
import { Var } from '../../vars/var.js';
import { Vars } from '../../vars/vars.js';

export class MacroCmdLet extends CmdLet implements InputInterceptLine {
  name = 'm';
  category = 'misc';
  help = 'manage macros';
  private static readonly USAGE: string = `Usage: m
m - show all macros

m name - create, modify or display a macro
  name    the name of the macro

m name ${CmdLet.DELETE_CHAR} - delete a macro
  name    the name of the macro to delete`;

  private current: string | null = null;
  private commands: string[] = [];

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

    const macro = Macros.delete(name);
    if (macro === null) {
      Output.writeln(`macro ${Output.green(name)} not set`);
    } else {
      Output.writeln(`deleted macro ${Output.green(name)}`);
    }
    return Var.ZERO;
  }

  private runSet(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseLiteral]);
    if (vars === null) return null;
    const [name] = vars as [string];
    this.commands = [];
    this.current = name;
    const macro = Macros.get(name);
    if (macro === null) {
      Output.writeln(`Creating macro '${Output.green(name)}'`);
    } else {
      Output.writeln(`Modifying macro '${Output.green(name)}'`);
      Output.writeln(macro.toString());
    }
    Input.setInterceptLine(this);
    return Var.ZERO;
  }

  startLines(): void {
    this.commands = [];
  }

  addLine(line: string): void {
    this.commands.push(line);
  }

  clearLines(): void {
    if (this.current != null) {
      const macro = new Macro(this.current, []);
      Macros.set(macro);
    }
  }

  saveLines(): void {
    if (this.current != null) {
      const macro = new Macro(this.current, this.commands);
      Macros.set(macro);
    }
  }

  cancelLines(): void {}

  private runShow(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;
    Output.writeln(Output.blue('Macros:'));
    for (const macro of Macros.all()) {
      Output.writeln(`${Output.green(macro.name)}:`, true);

      Output.writeln(macro.toString(), true);

      Output.writeln();
    }
    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(MacroCmdLet.USAGE);
    return Var.ZERO;
  }

  public static runSync(macro: Macro): Var {
    let ret = Var.ZERO;
    for (const [idx, command] of macro.commands.entries()) {
      if (command.length === 0) continue;
      if (command.charAt(0) === '#') continue;

      Output.writeln(`${Output.bold(Input.PROMPT)}${command}`);

      if (command.trim().length === 0) continue;

      const parser = new Parser(command.toString());
      const tokens = parser.tokenize();
      ret = Command.runSync(tokens);
      Vars.setRet(ret);

      /*
       * Don't print the return as the last command as we will print it as the
       * result of the macro command itself
       */
      if (idx !== macro.commands.length - 1) {
        Output.writeRet();
        Output.writeln();
      }
    }
    return ret;
  }
}
