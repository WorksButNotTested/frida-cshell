import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: log

log - clear log file

log file - set log file
  file      the file to log to`;

export class LogCmdLet extends CmdLet {
  name = 'log';
  category = 'misc';
  help = 'set log file';

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return this.usage();
    const [_, [file]] = vars as [[], [string | null]];
    if (file === null) {
      Output.clearLog();
      Output.writeln('log file cleared');
    } else {
      try {
        Output.writeln(
          [
            'log file set to ',
            Output.blue("'"),
            Output.green(file),
            Output.blue("'"),
          ].join(''),
        );
        Output.setLog(file);
      } catch {
        Output.writeln(`invalid log file: ${file}`);
      }
    }
    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(USAGE);
    return Var.ZERO;
  }
}
