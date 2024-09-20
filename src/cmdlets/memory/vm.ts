import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Regex } from '../../misc/regex.js';

export class VmCmdLet extends CmdLet {
  name = 'vm';
  category = 'memory';
  help = 'display virtual memory ranges';

  private static readonly USAGE: string = `Usage: vm

vm - show all mappings

vm address - show mapping for address
  address   the address/symbol to show mapping information for

vm module - show mappings for a module
  module    the name of the module to show mapping information for`;

  public runSync(tokens: Token[]): Var {
    const retWithAddress = this.runShowAddress(tokens);
    if (retWithAddress !== null) return retWithAddress;

    const retWithWildCard = this.runShowNamed(tokens);
    if (retWithWildCard !== null) return retWithWildCard;

    return this.usage();
  }

  private runShowAddress(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return null;
    const [v0] = vars as [Var];

    const address = v0.toPointer();

    const matches = Process.enumerateRanges('---').filter(
      r => r.base <= address && r.base.add(r.size) > address,
    );
    if (matches.length === 1) {
      const r = matches[0] as RangeDetails;
      Output.writeln(
        `Address: ${Format.toHexString(address)} is within allocation:`,
      );
      this.printMapping(r);
      return v0;
    } else {
      Output.writeln(
        `Address: ${Format.toHexString(address)} is not found within an allocation:`,
      );
      const before = Process.enumerateRanges('---').filter(
        r => r.base <= address,
      );
      if (before.length === 0) {
        Output.writeln('No previous mapping');
      } else {
        const r = before[before.length - 1] as RangeDetails;
        Output.writeln('Previous mapping');
        this.printMapping(r);
      }
      const after = Process.enumerateRanges('---').filter(
        r => r.base.add(r.size) > address,
      );
      if (after.length === 0) {
        Output.writeln('No next mapping');
      } else {
        const r = after[0] as RangeDetails;
        Output.writeln('Next mapping');
        this.printMapping(r);
      }
    }
    return v0;
  }

  private printMapping(r: RangeDetails, filter: boolean = true) {
    const limit = r.base.add(r.size);
    let fileInfo = '';
    if (r.file !== undefined) {
      fileInfo = [
        `offset: ${Output.yellow(Format.toHexString(r.file.offset))},`,
        `name: ${Output.blue(r.file.path)}`,
      ].join(' ');
    }
    Output.writeln(
      [
        `\t${Output.green(Format.toHexString(r.base))}-${Output.green(Format.toHexString(limit))}`,
        `${Output.bold(Output.yellow(r.protection))}`,
        `${Output.bold(Format.toSize(r.size))}`,
        fileInfo,
      ].join(' '),
      filter,
    );
  }

  private runShowNamed(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseLiteral]);
    if (vars === null) return null;
    const [_, [name]] = vars as [[], [string | null]];

    if (name === null) {
      Process.enumerateRanges('---').forEach(r => {
        this.printMapping(r, true);
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
        m.enumerateRanges('---').forEach(r => {
          this.printMapping(r, true);
        });
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
      }

      mod.enumerateRanges('---').forEach(r => {
        this.printMapping(r, true);
      });
      return new Var(uint64(mod.base.toString()), `Module: ${mod.name}`);
    }
  }

  public usage(): Var {
    Output.writeln(VmCmdLet.USAGE);
    return Var.ZERO;
  }
}
