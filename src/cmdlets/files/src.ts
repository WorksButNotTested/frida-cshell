import { CmdLetBase } from '../../commands/cmdlet.js';
import { CharCode } from '../../io/char.js';
import { Input } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { History } from '../../terminal/history.js';
import { Var } from '../../vars/var.js';

export class SrcCmdLet extends CmdLetBase {
  name = 'src';
  category = 'files';
  help = 'run commands from file';

  private static readonly USAGE: string = `Usage: src

src path - run commands from file
  path      the absolute path of the file to load (note that paths with spaces must be quoted)`;

  private static lastPath: string | null = null;

  public static async loadInitScript(path: string) {
    this.lastPath = path;
    const src = new SrcCmdLet();
    await src.runScript(path);
  }

  public override runSync(_tokens: Token[]): Var {
    throw new Error("can't run in synchronous mode");
  }

  public override async run(tokens: Token[]): Promise<Var> {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return this.usage();
    // eslint-disable-next-line prefer-const
    let [_, [name]] = vars as [[], [string | null]];
    if (name === null) {
      if (SrcCmdLet.lastPath === null) throw new Error('path not initialized');

      await this.runScript(SrcCmdLet.lastPath);
      return Var.ZERO;
    } else {
      if (name.length > 1 && name.startsWith('"') && name.endsWith('"')) {
        name = name.slice(1, name.length - 1);
      }

      SrcCmdLet.lastPath = name;
      await this.runScript(name);

      return Var.ZERO;
    }
  }

  private async runScript(path: string) {
    try {
      Output.writeln(`Loading: ${Output.green(path)}`);

      const initScript = File.readAllText(path);
      const lines = initScript.split('\n');

      History.clearLine();
      Input.prompt();

      for (const line of lines) {
        if (line.length === 0) continue;
        if (line.charAt(0) === '#') continue;
        Output.write(line);
        await Input.read(`${line}${String.fromCharCode(CharCode.CR)}`);
      }

      Output.clearLine();
      Output.writeln(`Loaded: ${Output.green(path)}`);
    } catch (_) {
      /* Ignore the error */
    }
  }

  public usage(): Var {
    Output.writeln(SrcCmdLet.USAGE);
    return Var.ZERO;
  }
}
