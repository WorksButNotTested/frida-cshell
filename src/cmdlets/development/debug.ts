import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class DebugCmdLet extends CmdLetBase {
  name = 'debug';
  category = 'development';
  help = 'toggle debug mode';

  private static readonly USAGE: string = `Usage: debug
debug - toggle debug mode`;

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
    Output.writeln(DebugCmdLet.USAGE);
    return Var.ZERO;
  }
}
