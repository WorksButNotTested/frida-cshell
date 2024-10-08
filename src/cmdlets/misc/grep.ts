import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class GrepCmdLet extends CmdLetBase {
  name = 'grep';
  category = 'misc';
  help = 'filter output';

  private static readonly USAGE: string = `Usage: grep

grep - clear output filter

grep regex - filter output
  regex      the regex to use to filter the output`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return this.usage();
    // eslint-disable-next-line prefer-const
    let [_, [filter]] = vars as [[], [string | null]];
    if (filter === null) {
      Output.clearFilter();
      Output.writeln('output filter cleared');
    } else {
      try {
        if (
          filter.length > 1 &&
          filter.startsWith('"') &&
          filter.endsWith('"')
        ) {
          filter = filter.slice(1, filter.length - 1);
        }
        Output.setFilter(filter);
        Output.writeln(
          [
            'output filter set to ',
            Output.blue("'"),
            Output.green(filter),
            Output.blue("'"),
          ].join(''),
        );
      } catch {
        Output.writeln(`invalid regex: ${filter}`);
      }
    }
    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(GrepCmdLet.USAGE);
    return Var.ZERO;
  }
}
