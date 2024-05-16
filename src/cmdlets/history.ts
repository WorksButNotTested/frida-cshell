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

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private runWithId(tokens: Token[]): Var | undefined {
    if (tokens.length !== 1) return undefined;

    const id = tokens[0]?.toVar()?.toU64().toNumber();
    if (id === undefined) return undefined;

    return History.rerun(id);
  }

  private runWithoutId(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    const history = Array.from(History.all());
    for (const [i, value] of history.entries()) {
      Output.writeln(`${i.toString().padStart(3, ' ')}: ${value}`);
    }
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithId = this.runWithId(tokens);
    if (retWithId !== undefined) return retWithId;

    const retWithoutId = this.runWithoutId(tokens);
    if (retWithoutId !== undefined) return retWithoutId;

    return this.usage();
  }
}
