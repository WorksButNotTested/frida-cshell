import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { History } from '../terminal/history.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: h

h - show history

h index - rerun history item
  index   the index of the item to rerun
`;

export class HistoryCmdLet extends CmdLet {
  name = 'h';
  category = 'misc';
  help = 'command history';

  public runSync(_tokens: Token[]): Var {
    throw new Error('not supported');
  }

  public override async run(tokens: Token[]): Promise<Var> {
    const vars = this.transformOptional(tokens, [], [this.parseVar]);
    if (vars === null) return this.usage();
    const [[], [v0]] = vars as [[], [Var | null]];

    if (v0 === null) {
      const history = Array.from(History.all());
      for (const [i, value] of history.entries()) {
        Output.writeln(`${i.toString().padStart(3, ' ')}: ${value}`);
      }
      return Var.ZERO;
    } else {
      const id = v0.toU64().toNumber();

      return History.rerun(id);
    }
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
