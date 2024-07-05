import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

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

  public runSync(tokens: Token[]): Var {
    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== null) return retWithAddress;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    const retWithoutName = this.runWithoutName(tokens);
    if (retWithoutName !== null) return retWithoutName;

    return this.usage();
  }

  private runWithAddress(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const address = v0.toPointer();

    const matches = Process.enumerateModules().filter(
      m => m.base <= address && m.base.add(m.size) > address,
    );
    if (matches.length === 1) {
      const m = matches[0] as Module;
      Output.writeln(
        `Address: ${Format.toHexString(address)} is within module:`,
      );
      this.printModule(m);
    } else {
      Output.writeln(
        `Address: ${Format.toHexString(address)} is not found within a module:`,
      );
    }
    return v0;
  }

  private printModule(m: Module) {
    const limit = m.base.add(m.size);
    Output.write(
      `${Output.green(Format.toHexString(m.base))}-${Output.green(Format.toHexString(limit))} `,
    );
    Output.write(`${Output.bold(Format.toSize(m.size))} `);
    Output.write(`${Output.yellow(m.name.padEnd(30, ' '))} `);
    Output.write(`${Output.blue(m.path)}`);
    Output.writeln();
  }

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();

    const mod = Process.findModuleByName(name);
    if (mod === null) {
      Output.writeln(`Module: ${name} not found`);
      return Var.ZERO;
    } else {
      this.printModule(mod);
      return new Var(uint64(mod.base.toString()));
    }
  }

  private runWithoutName(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    const modules = Process.enumerateModules();
    modules.sort((a, b) => a.base.compare(b.base));
    modules.forEach(m => {
      this.printModule(m);
    });
    return Var.ZERO;
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
