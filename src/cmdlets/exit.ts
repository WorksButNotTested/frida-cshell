import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Token } from '../token.js';
import { Var } from '../var.js';

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
