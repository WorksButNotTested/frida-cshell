import { BpType } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import {
  BpCodeInstruction,
  BpFunctionEntry,
  BpFunctionExit,
} from '../../breakpoints/code.js';
import { BpCoverage } from '../../breakpoints/trace.js';
import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { TypedBpCmdLet } from './bp.js';

abstract class CodeBpCmdLet extends TypedBpCmdLet {
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[addr], [hits, cond]] = vars as [
      [Var],
      [number | null, number | null],
    ];
    const conditional = cond === null ? false : true;

    const idx = Bps.getNextFreeIndex(this.bpType);
    switch (this.bpType) {
      case BpType.Instruction: {
        const bp = new BpCodeInstruction(idx, addr, hits);
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.FunctionEntry: {
        const bp = new BpFunctionEntry(idx, addr, hits);
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.FunctionExit: {
        const bp = new BpFunctionExit(idx, addr, hits);
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.Coverage: {
        const bp = new BpCoverage(idx, addr, hits);
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      default:
        throw new Error(`unexpected breakpoint type: ${this.bpType}`);
    }

    return Var.fromId(idx);
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[index, addr], [hits, cond]] = vars as [
      [number, Var],
      [number | null, string | null],
    ];

    const conditional = cond === null ? false : true;

    const bp = Bps.get(this.bpType, index);
    if (bp === null) throw new Error(`breakpoint #${index} doesn't exist`);

    Bps.checkOverlaps(bp);

    bp.disable();
    bp.address = addr;
    bp.hits = hits ?? -1;

    Output.writeln(`Modified ${bp.toString()}`);
    this.editBreakpoint(bp, conditional);

    return Var.fromId(index);
  }

  protected override usageCreate(): string {
    const usage: string = `
${this.name} 0 - create ${this.bpType} breakpoint without assigning an address

${this.name} addr - create ${this.bpType} breakpoint without a hit limit
   addr    the address to create the breakpoint

${this.name} addr hits - create ${this.bpType} breakpoint
   addr    the address to create the breakpoint
   hits    the number of times the breakpoint should fire

${this.name} addr hits ${TypedBpCmdLet.CONDITIONAL_CHAR} - create ${this.bpType} breakpoint with conditions
   addr    the address to create the breakpoint
   hits    the number of times the breakpoint should fire
   `;

    return usage;
  }

  protected override usageModify(): string {
    const usage: string = `
${this.name} ${CmdLetBase.NUM_CHAR}n addr - modify a ${this.bpType} breakpoint without a hit limit
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint

${this.name} ${CmdLetBase.NUM_CHAR}n addr hits - modify a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   hits    the number of times the breakpoint should fire

${this.name} ${CmdLetBase.NUM_CHAR}n addr hits ${TypedBpCmdLet.CONDITIONAL_CHAR} - modify a ${this.bpType} breakpoint with conditions
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   hits    the number of times the breakpoint should fire`;
    return usage;
  }
}

export class InsnBpCmdLet extends CodeBpCmdLet {
  name = '@i';
  bpType = BpType.Instruction;
  help = `${this.bpType} breakpoint`;
}

export class FunctionEntryBpCmdLet extends CodeBpCmdLet {
  name = '@f';
  bpType = BpType.FunctionEntry;
  help = `${this.bpType} breakpoint`;
}

export class FunctionExitBpCmdLet extends CodeBpCmdLet {
  name = '@F';
  bpType = BpType.FunctionExit;
  help = `${this.bpType} breakpoint`;
}

export class CoverageBpCmdLet extends CodeBpCmdLet {
  name = '@c';
  bpType = BpType.Coverage;
  help = `${this.bpType} breakpoint`;
}
