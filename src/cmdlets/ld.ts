import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: ld

ld - load a module

ld path - load a module
  path      the absolute path of the module to load (note that paths with spaces must be quoted)
`;

export class LdCmdLet extends CmdLet {
  name = 'ld';
  category = 'modules';
  help = 'load modules';

  public run(tokens: Token[]): Var {
    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    let name = t0.getLiteral();

    if (name.length > 1 && name.startsWith('"') && name.endsWith('"'))
      name = name.slice(1, name.length - 1);

    /* "/workspaces/frida-cshell/module.so" */
    Output.writeln(`Loading: ${name}`);

    const mod = Module.load(name);
    return new Var(mod.base.toString());
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
