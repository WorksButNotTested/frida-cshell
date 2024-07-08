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

  public static readonly defaultPath = `${Process.getHomeDir()}/.cshellrc`;
  private lastPath = SrcCmdLet.defaultPath;

  public static loadInitScript() {
    const src = new SrcCmdLet();
    src.runScript(SrcCmdLet.defaultPath);
  }

  public runSync(tokens: Token[]): Var {
    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    const retWithoutName = this.runWithoutName(tokens);
    if (retWithoutName !== null) return retWithoutName;

    return this.usage();
  }

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    let name = t0.getLiteral();

    if (name.length > 1 && name.startsWith('"') && name.endsWith('"'))
      name = name.slice(1, name.length - 1);

    Output.writeln(`Loading: ${name}`);
    this.lastPath = name;
    this.runScript(name);

    return Var.ZERO;
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

        const parser = new Parser(line.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } catch (_) {}
  }

  private runWithoutName(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    Output.writeln(`Loading: ${this.lastPath}`);
    this.runScript(this.lastPath);
    return Var.ZERO;
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
