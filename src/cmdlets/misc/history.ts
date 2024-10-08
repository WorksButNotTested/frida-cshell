import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { History } from '../../terminal/history.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class HistoryCmdLet extends CmdLetBase {
  name = 'h';
  category = 'misc';
  help = 'command history';

  private static readonly USAGE: string = `Usage: h

h - show history

h index - rerun history item
  index   the index of the item to rerun`;

  public runSync(_tokens: Token[]): Var {
    throw new Error('not supported');
  }

  public override async run(tokens: Token[]): Promise<Var> {
    const vars = this.transformOptional(tokens, [], [this.parseVar]);
    if (vars === null) return this.usage();
    const [_, [v0]] = vars as [[], [Var | null]];

    if (v0 === null) {
      const history = Array.from(History.all());
      for (const [i, value] of history.entries()) {
        Output.writeln(
          [`${i.toString().padStart(3, ' ')}:`, value].join(' '),
          true,
        );
      }
      return Var.ZERO;
    } else {
      const id = v0.toU64().toNumber();

      return History.rerun(id);
    }
  }

  public usage(): Var {
    Output.writeln(HistoryCmdLet.USAGE);
    return Var.ZERO;
  }
}
