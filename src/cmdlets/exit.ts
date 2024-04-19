import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

export class ExitCmdLet extends CmdLet {
  name = 'exit';
  category = 'misc';
  help = 'exits the shell';
  override visible = false;

  public usage(): Var {
    Output.writeln('Press CTRL+C to exit.');
    return Var.ZERO;
  }

  public run(_: Token[]): Var {
    return this.usage();
  }
}
