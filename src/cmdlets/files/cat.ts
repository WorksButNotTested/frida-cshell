import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class CatCmdLet extends CmdLet {
  name = 'cat';
  category = 'files';
  help = 'dump a file';

  private static readonly USAGE: string = `Usage: cat

cat file - dump file
  file      the file to dump`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseLiteral]);
    if (vars === null) return this.usage();

    const [file] = vars as [string];
    Output.writeln(`Dumping file: ${Output.green(file)}`);

    try {
      const text = File.readAllText(file);
      const lines = text.split('\n');
      lines.forEach(l => Output.writeln(Output.yellow(l), true));
    } catch {
      Output.writeln(`failed to read file: ${Output.green(file)}`);
    }

    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(CatCmdLet.USAGE);
    return Var.ZERO;
  }
}
