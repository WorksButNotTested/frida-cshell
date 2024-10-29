import { Bp, BpType } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import {
  BpBlockTrace,
  BpCallTrace,
  BpCoverage,
  BpTrace,
  BpUniqueBlockTrace,
} from '../../breakpoints/trace.js';
import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { TypedBpCmdLet } from './bp.js';

abstract class TraceBpCmdLet extends TypedBpCmdLet {
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[addr, depth], [hits, cond]] = vars as [
      [Var, Var],
      [number | null, string | null],
    ];
    const conditional = cond === null ? false : true;

    if (addr.isNull()) return null;

    const idx = Bps.getNextFreeIndex(this.bpType);
    switch (this.bpType) {
      case BpType.BlockTrace: {
        const bp = new BpBlockTrace(idx, addr, hits, depth.toU64().toNumber());
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.CallTrace: {
        const bp = new BpCallTrace(idx, addr, hits, depth.toU64().toNumber());
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.UniqueBlockTrace: {
        const bp = new BpUniqueBlockTrace(
          idx,
          addr,
          hits,
          depth.toU64().toNumber(),
        );
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.Coverage: {
        const bp = new BpCoverage(idx, addr, hits, depth.toU64().toNumber());
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      default:
        throw new Error(`unexpected breakpoint type: ${this.bpType}`);
    }

    return Bp.idToVar(idx);
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[index, addr, depth], [hits, cond]] = vars as [
      [number, Var, Var],
      [number | null, string | null],
    ];

    const conditional = cond === null ? false : true;

    if (addr.isNull()) return null;

    const bp = Bps.get(this.bpType, index) as BpTrace;
    if (bp === null) throw new Error(`breakpoint #${index} doesn't exist`);

    Bps.checkOverlaps(bp);

    bp.disable();
    bp.address = addr;
    bp.depth = depth.toU64().toNumber();
    bp.hits = hits ?? -1;

    Output.writeln(`Modified ${bp.toString()}`);
    this.editBreakpoint(bp, conditional);

    return Bp.idToVar(index);
  }

  protected override usageCreate(): string {
    const usage: string = `
${this.name} addr depth - create ${this.bpType} breakpoint without a hit limit
   addr    the address to create the breakpoint
   depth   the maximum depth of callstack to follow

${this.name} addr depth hits - create ${this.bpType} breakpoint
   hits    the number of times the breakpoint should fire
   addr    the address to create the breakpoint
   depth   the maximum depth of callstack to follow

${this.name} addr depth hits ${TypedBpCmdLet.CONDITIONAL_CHAR} - create ${this.bpType} breakpoint with conditions
   hits    the number of times the breakpoint should fire
   addr    the address to create the breakpoint
   depth   the maximum depth of callstack to follow`;
    return usage;
  }

  protected override usageModify(): string {
    const usage: string = `
${this.name} ${CmdLetBase.NUM_CHAR}n addr depth - modify a ${this.bpType} breakpoint without a hit limit
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   depth   the maximum depth of callstack to follow

${this.name} ${CmdLetBase.NUM_CHAR}n addr depth hits - modify a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   depth   the maximum depth of callstack to follow
   hits    the number of times the breakpoint should fire

${this.name} ${CmdLetBase.NUM_CHAR}n addr depth hits ${TypedBpCmdLet.CONDITIONAL_CHAR} - modify a ${this.bpType} breakpoint with conditions
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   depth   the maximum depth of callstack to follow
   hits    the number of times the breakpoint should fire`;
    return usage;
  }
}

export class BlockTraceBpCmdLet extends TraceBpCmdLet {
  name = '@tb';
  bpType = BpType.BlockTrace;
  help = `${this.bpType} breakpoint`;
}

export class CallTraceBpCmdLet extends TraceBpCmdLet {
  name = '@tc';
  bpType = BpType.CallTrace;
  help = `${this.bpType} breakpoint`;
}

export class UniqueBlockTraceBpCmdLet extends TraceBpCmdLet {
  name = '@tbu';
  bpType = BpType.UniqueBlockTrace;
  help = `${this.bpType} breakpoint`;
}
