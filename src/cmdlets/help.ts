import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { CmdLets } from '../commands/cmdlets.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

export class HelpCmdLet extends CmdLet {
  name = 'help';
  category = 'misc';
  help = 'print this message';

  public runSync(tokens: Token[]): Var {
    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();

    const cmdlet = CmdLets.getByName(name);
    if (cmdlet === null) return null;

    return cmdlet.usage();
  }

  public usage(): Var {
    const cmdlets = CmdLets.all().filter(c => c.visible);
    const groups: Map<string, CmdLet[]> = cmdlets.reduce((result, item) => {
      const category = item.category;
      if (!result.has(category)) {
        result.set(category, []);
      }

      result.get(category)?.push(item);
      return result;
    }, new Map<string, CmdLet[]>());

    Array.from(groups.entries())
      .sort(([k1, _v1], [k2, _v2]) => k1.localeCompare(k2))
      .forEach(([k, v]) => {
        Output.writeln(`${Output.bold(k)}:`);
        Array.from(v)
          .sort((c1, c2) => c1.name.localeCompare(c2.name))
          .forEach(c => {
            Output.writeln(`\t${c.name.padEnd(10, ' ')}:  ${c.help}`);
          });
      });

    Output.writeln();
    Output.writeln('For more information about a command use:');
    Output.writeln('\thelp <cmd>');
    return Var.ZERO;
  }
}
