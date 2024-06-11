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

  public runSync(tokens: Token[]): Var {
    throw new Error('not supported');
  }

  public override async run(tokens: Token[]): Promise<Var> {
    const retWithId = await this.runWithId(tokens);
    if (retWithId !== null) return retWithId;

    const retWithoutId = this.runWithoutId(tokens);
    if (retWithoutId !== null) return retWithoutId;

    return this.usage();
  }

  private async runWithId(tokens: Token[]): Promise<Var | null> {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const id = v0.toU64().toNumber();

    return History.rerun(id);
  }

  private runWithoutId(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    const history = Array.from(History.all());
    for (const [i, value] of history.entries()) {
      Output.writeln(`${i.toString().padStart(3, ' ')}: ${value}`);
    }
    return Var.ZERO;
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
