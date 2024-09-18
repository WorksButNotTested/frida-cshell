import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: verbose
verbose - toggle verbose mode`;

export class VerboseCmdLet extends CmdLet {
  name = 'verbose';
  category = 'misc';
  help = 'toggle verbose mode';

  public runSync(_tokens: Token[]): Var {
    const verbose = !Output.getVerbose();
    if (verbose) {
      Output.writeln(`verbose mode ${Output.green('enabled')}`);
    } else {
      Output.writeln(`verbose mode ${Output.red('disabled')}`);
    }
    Output.setVerbose(verbose);

    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(USAGE);
    return Var.ZERO;
  }
}
