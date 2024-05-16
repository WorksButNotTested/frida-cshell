import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: vm

vm - show all mappings

vm address - show mapping for address
  address   the address/symbol to show mapping information for

vm module - show mappings for a module
  module    the name of the module to show mapping information for
`;

export class VmCmdLet extends CmdLet {
  name = 'vm';
  category = 'memory';
  help = 'display virtual memory ranges';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private printMapping(r: RangeDetails) {
    const limit = r.base.add(r.size);
    if (r.file === undefined)
      Output.writeln(
        `\t${Format.toHexString(r.base)}-${Format.toHexString(limit)} ${r.protection} ${Format.toSize(r.size)}`,
      );
    else
      Output.writeln(
        `\t${Format.toHexString(r.base)}-${Format.toHexString(limit)} ${r.protection} ${Format.toSize(r.size)} offset: ${Format.toHexString(r.file.offset)}, name: ${r.file.path}`,
      );
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length !== 1) return undefined;

    const t0 = tokens[0] as Token;

    const v0 = t0.toVar();
    if (v0 === null) return undefined;

    const address = v0.toPointer();
    if (address === undefined) return undefined;

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

  private runWithName(tokens: Token[]): Var | undefined {
    if (tokens.length !== 1) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const mod = Process.findModuleByName(name);
    if (mod === null) {
      Output.writeln(`Module: ${name} not found`);
      return Var.ZERO;
    }

    mod.enumerateRanges('---').forEach(r => {
      this.printMapping(r);
    });
    return Var.ZERO;
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Process.enumerateRanges('---').forEach(r => {
      this.printMapping(r);
    });
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }
}
