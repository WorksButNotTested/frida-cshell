import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class LogCmdLet extends CmdLetBase {
  name = 'log';
  category = 'misc';
  help = 'set log file';

  private static readonly USAGE: string = `Usage: log

log - clear log file

log file - set log file
  file      the file to log to`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(tokens, [], [this.parseString]);
    if (vars === null) return this.usage();
    const [_, [file]] = vars as [[], [string | null]];
    if (file === null) {
      const logName = Output.clearLog();
      Output.writeln('log file cleared');
      if (logName === null) {
        return Var.ZERO;
      } else {
        return new Var(logName);
      }
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
      return new Var(file);
    }
  }

  public usage(): Var {
    Output.writeln(LogCmdLet.USAGE);
    return Var.ZERO;
  }
}
