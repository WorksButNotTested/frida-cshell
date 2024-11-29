import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class LdCmdLet extends CmdLetBase {
  name = 'ld';
  category = 'modules';
  help = 'load modules';

  private static readonly USAGE: string = `Usage: ld

ld - load a module

ld path - load a module
  path      the absolute path of the module to load (note that paths with spaces must be quoted)`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseString]);
    if (vars === null) return this.usage();
    let [name] = vars as [string];

    if (name.length > 1 && name.startsWith('"') && name.endsWith('"')) {
      name = name.slice(1, name.length - 1);
    }

    /* "/workspaces/frida-cshell/module.so" */
    Output.writeln(`Loading: ${name}`);

    const mod = Module.load(name);
    return new Var(mod.base.toString(), `Module: ${name}`);
  }

  public usage(): Var {
    Output.writeln(LdCmdLet.USAGE);
    return Var.ZERO;
  }
}
