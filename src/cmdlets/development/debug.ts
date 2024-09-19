import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

const USAGE: string = `Usage: debug
debug - toggle debug mode`;

export class DebugCmdLet extends CmdLet {
  name = 'debug';
  category = 'development';
  help = 'toggle debug mode';

  public runSync(_tokens: Token[]): Var {
    const debug = !Output.getDebugging();
    if (debug) {
      Output.writeln(`debug mode ${Output.green('enabled')}`);
    } else {
      Output.writeln(`debug mode ${Output.red('disabled')}`);
    }
    Output.setDebugging(debug);

    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(USAGE);
    return Var.ZERO;
  }
}
