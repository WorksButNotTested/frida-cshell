import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { TypedBpCmdLet } from './bp.js';
import { Bp, BpType } from '../../breakpoints/bp.js';
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
      bp.enable();
      Output.writeln(`Created ${bp.toString()}`);
      return Bp.idToVar(index);
    } catch (error) {
      throw new Error(`failed to replace ${address} with ${target}, ${error}`);
    }
  }

  /*
   * This function doesn't actually modify the breakpoint, but rather since it
   * is called berfore runShow in the parent it allows us to match those same
   * arguments and overload it to return the trampoline address in the event
   * that a breakpoint id was specified.
   */
  protected override runModify(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseIndex]);
    if (vars === null) return null;
    const [index] = vars as [number];
    const bp = Bps.get(this.bpType, index) as BpReplacement;
    if (bp === null) throw new Error(`breakpoint #${index} doesn't exist`);
    Output.writeln(bp.toString());
    return bp.trampoline;
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
