import { CmdLet } from '../commands/cmdlet.js';
import { Command } from '../commands/command.js';
import { Input } from '../io/input.js';
import { Output } from '../io/output.js';
import { Parser } from '../io/parser.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Vars } from '../vars/vars.js';

const USAGE: string = `Usage: src

src path - load script
  path      the absolute path of the script to load (note that paths with spaces must be quoted)
`;

export class SrcCmdLet extends CmdLet {
  name = 'src';
  category = 'misc';
  help = 'load script';

  private static lastPath: string | null = null;

  public static loadInitScript(path: string) {
    this.lastPath = path;
    const src = new SrcCmdLet();
    src.runScript(path);
  }

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return this.usage();
    let [[], [name]] = vars as [[], [string | null]];
    if (name === null) {
      if (SrcCmdLet.lastPath === null) throw new Error('path not initialized');

      Output.writeln(`Loading: ${SrcCmdLet.lastPath}`);
      this.runScript(SrcCmdLet.lastPath);
      return Var.ZERO;
    } else {
      if (name.length > 1 && name.startsWith('"') && name.endsWith('"')) {
        name = name.slice(1, name.length - 1);
      }

      Output.writeln(`Loading: ${name}`);
      SrcCmdLet.lastPath = name;
      this.runScript(name);

      return Var.ZERO;
    }
  }

  private runScript(path: string) {
    try {
      const initScript = File.readAllText(path);
      const lines = initScript.split('\n');
      for (const line of lines) {
        if (line.length === 0) continue;
        if (line.charAt(0) === '#') continue;

        Output.write(Output.bold(Input.PROMPT));
        Output.writeln(line);

        if (line.trim().length === 0) continue;

        const parser = new Parser(line.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } catch (_) {}
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
