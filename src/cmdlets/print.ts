import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: p
p - print an expression

p exp - print an expression
  exp   the expression to print
`;

export class PrintCmdLet extends CmdLet {
  name = 'p';
  category = 'misc';
  help = 'print an expression';

  public runSync(tokens: Token[]): Var {
    const retWithExpression = this.runWithExpression(tokens);
    if (retWithExpression !== null) return retWithExpression;

    return this.usage();
  }

  private runWithExpression(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t = tokens[0] as Token;
    if (t === null) return null;

    const val = t.toVar();
    if (val === null) {
      Output.writeln(t.getLiteral());
      return Var.ZERO;
    }

    Output.writeln(`${t.getLiteral()} = ${val}`);
    return val;
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
