import { CmdLetBase } from '../../commands/cmdlet.js';
import { CharCode } from '../../io/char.js';
import { Input } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Format } from '../../misc/format.js';
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
    const vars = this.transformOptional(tokens, [], [this.parseString]);
    if (vars === null) return this.usage();
    // eslint-disable-next-line prefer-const
    let [_, [name]] = vars as [[], [string | null]];
    if (name === null) {
      if (SrcCmdLet.lastPath === null) throw new Error('path not initialized');

      await this.runScript(SrcCmdLet.lastPath);
      return new Var(SrcCmdLet.lastPath);
    } else {
      SrcCmdLet.lastPath = name;
      await this.runScript(name);
      return new Var(name);
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
        const bytes = Format.toByteArray(
          `${line}${String.fromCharCode(CharCode.CR)}`,
        );
        await Input.read(bytes);
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
