import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Util } from '../misc/util.js';
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
        `\t${Util.toHexString(r.base)}-${Util.toHexString(limit)} ${r.protection} ${Util.toSize(r.size)}`,
      );
    else
      Output.writeln(
        `\t${Util.toHexString(r.base)}-${Util.toHexString(limit)} ${r.protection} ${Util.toSize(r.size)} offset: ${Util.toHexString(r.file.offset)}, name: ${r.file.path}`,
      );
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return undefined;

    const address = t0.toPointer();
    if (address === undefined) return undefined;

    const matches = Process.enumerateRanges('---').filter(
      r => r.base <= address && r.base.add(r.size) > address,
    );
    if (matches.length === 1) {
      const r = matches[0] as RangeDetails;
      Output.writeln(
        `Address: ${Util.toHexString(address)} is within allocation:`,
      );
      this.printMapping(r);
      return t0;
    } else {
      Output.writeln(
        `Address: ${Util.toHexString(address)} is not found within an allocation:`,
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
