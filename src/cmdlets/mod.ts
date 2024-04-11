import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Util } from '../util.js';
import { Token } from '../token.js';
import { Var } from '../var.js';

const USAGE: string = `Usage: mod

mod - show all modules

mod address - show module for address
  address   the address/symbol to show module information for

mod name - show named module
  name      the name of the module to show information for
`;

export class ModCmdLet extends CmdLet {
  name = 'mod';
  category = 'modules';
  help = 'display module information';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private printModule(m: Module) {
    const limit = m.base.add(m.size);
    Output.writeln(
      `${Util.toHexString(m.base)}-${Util.toHexString(limit)} ${Util.toSize(m.size)} ${m.name.padEnd(30, ' ')} ${m.path}`,
    );
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return undefined;

    const address = t0.toPointer();
    if (address === undefined) return undefined;

    const matches = Process.enumerateModules().filter(
      m => m.base <= address && m.base.add(m.size) > address,
    );
    if (matches.length === 1) {
      const m = matches[0] as Module;
      Output.writeln(`Address: ${Util.toHexString(address)} is within module:`);
      this.printModule(m);
    } else {
      Output.writeln(
        `Address: ${Util.toHexString(address)} is not found within a module:`,
      );
    }
    return t0;
  }

  private runWithName(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const mod = Process.findModuleByName(name);
    if (mod === null) {
      Output.writeln(`Module: ${name} not found`);
      return Var.ZERO;
    } else {
      this.printModule(mod);
      return Var.ZERO;
    }
  }

  private runWithoutName(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Process.enumerateModules().forEach(m => {
      this.printModule(m);
    });
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    const retWithoutName = this.runWithoutName(tokens);
    if (retWithoutName !== undefined) return retWithoutName;

    return this.usage();
  }
}
