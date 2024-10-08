import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class PrintCmdLet extends CmdLetBase {
  name = 'p';
  category = 'misc';
  help = 'print an expression';

  private static readonly USAGE: string = `Usage: p
p - print an expression

p exp - print an expression
  exp   the expression to print`;

  public runSync(tokens: Token[]): Var {
    if (tokens.length !== 1) return this.usage();
    const t = tokens[0] as Token;
    const val = t.toVar();

    if (val === null) {
      Output.writeln(t.getLiteral());
      return Var.ZERO;
    } else {
      Output.writeln(`${t.getLiteral()} = ${val}`);
      return val;
    }
  }

  public usage(): Var {
    Output.writeln(PrintCmdLet.USAGE);
    return Var.ZERO;
  }
}
