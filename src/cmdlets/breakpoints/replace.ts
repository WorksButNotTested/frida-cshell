import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { TypedBpCmdLet } from './bp.js';
import { BpType } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import { BpReplacement } from '../../breakpoints/replace.js';
import { Output } from '../../io/output.js';

export class ReplaceCmdLet extends TypedBpCmdLet {
  name = 'replace';
  bpType = BpType.Replacement;
  help = `replace a function with another implementation (returns the address of the trampoline)`;

  public runCreate(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar, this.parseVar]);
    if (vars === null) return null;
    const [address, target] = vars as [Var, Var];

    try {
      const index = Bps.getNextFreeIndex(this.bpType);
      const bp = new BpReplacement(index, address, target);
      Bps.add(bp);
      Output.writeln(`Created ${bp.toString()}`);
      bp.enable();
      return bp.trampoline;
    } catch (error) {
      throw new Error(`failed to replace ${address} with ${target}, ${error}`);
    }
  }

  protected override runModify(_tokens: Token[]): Var | null {
    return null;
  }

  protected override usageCreate(): string {
    const usage: string = `
replace dest src - replace function
  dest   the address/symbol of the function to replace
  src    the address/symbol of the function to replace with`;
    return usage;
  }

  protected override usageModify(): string {
    return Output.bold('unsupported');
  }
}
