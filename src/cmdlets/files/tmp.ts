import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Files } from '../../misc/files.js';
import { Var } from '../../vars/var.js';

export class TmpCmdLet extends CmdLetBase {
  name = 'tmp';
  category = 'files';
  help = 'generate a temporary filename';

  private static readonly USAGE: string = `Usage: tmp

temp ext - generate temporary filename
  ext      the extension for the filename`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseString]);
    if (vars === null) return this.usage();

    const [ext] = vars as [string];

    const filename = Files.getRandomFileName(ext);
    return new Var(filename);
  }

  public usage(): Var {
    Output.writeln(TmpCmdLet.USAGE);
    return Var.ZERO;
  }
}
