import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Regex } from '../../misc/regex.js';

const USAGE: string = `Usage: mod

mod - show all modules

mod address - show module for address
  address   the address/symbol to show module information for

mod name - show named module
  name      the name of the module to show information for`;

export class ModCmdLet extends CmdLet {
  name = 'mod';
  category = 'modules';
  help = 'display module information';

  public runSync(tokens: Token[]): Var {
    const retWithAddress = this.runShowAddress(tokens);
    if (retWithAddress !== null) return retWithAddress;

    const retWithName = this.runShowNamed(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private runShowAddress(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return null;
    const [v0] = vars as [Var];

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

  private printModule(m: Module, filtered: boolean = true) {
    const limit = m.base.add(m.size);
    Output.writeln(
      [
        `${Output.green(Format.toHexString(m.base))}-${Output.green(Format.toHexString(limit))}`,
        Output.bold(Format.toSize(m.size)),
        Output.yellow(m.name.padEnd(30, ' ')),
        Output.blue(m.path),
      ].join(' '),
      filtered,
    );
  }

  private runShowNamed(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return null;
    const [_, [name]] = vars as [[], [string | null]];

    if (name === null) {
      const modules = Process.enumerateModules();
      modules.sort((a, b) => a.base.compare(b.base));
      modules.forEach(m => {
        this.printModule(m);
      });
      return Var.ZERO;
    } else if (Regex.isGlob(name)) {
      const regex = Regex.globToRegex(name);
      if (regex === null) return this.usage();

      const modules = Process.enumerateModules().filter(m =>
        m.name.match(regex),
      );
      modules.sort();
      modules.forEach(m => {
        this.printModule(m, true);
      });
      if (modules.length === 1) {
        const module = modules[0] as Module;
        return new Var(
          uint64(module.base.toString()),
          `Module: ${module.name}`,
        );
      } else {
        return Var.ZERO;
      }
    } else {
      const mod = Process.findModuleByName(name);
      if (mod === null) {
        Output.writeln(`Module: ${name} not found`);
        return Var.ZERO;
      } else {
        this.printModule(mod);
        return new Var(uint64(mod.base.toString()), `Module: ${mod.name}`);
      }
    }
  }

  public usage(): Var {
    Output.writeln(USAGE);
    return Var.ZERO;
  }
}
