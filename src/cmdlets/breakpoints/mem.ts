import { BpType } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import { BpReadMemory, BpWriteMemory } from '../../breakpoints/memory.js';
import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { TypedBpCmdLet } from './bp.js';

abstract class MemoryBpCmdLet extends TypedBpCmdLet {
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[addr, length], [hits, cond]] = vars as [
      [Var, Var],
      [number | null, string | null],
    ];
    const conditional = cond === null ? false : true;

    const idx = Bps.getNextFreeIndex(this.bpType);
    switch (this.bpType) {
      case BpType.MemoryRead: {
        const bp = new BpReadMemory(idx, addr, length.toU64().toNumber(), hits);
        Bps.add(bp);
        Output.writeln(`Created ${bp.toString()}`);
        this.editBreakpoint(bp, conditional);
        break;
      }
      case BpType.MemoryWrite: {
        const bp = new BpWriteMemory(
          idx,
          addr,
          length.toU64().toNumber(),
          hits,
        );
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
      [this.parseIndex, this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[index, addr, length], [hits, cond]] = vars as [
      [number, Var, Var],
      [number | null, string | null],
    ];
    const conditional = cond === null ? false : true;

    const bp = Bps.get(this.bpType, index);
    if (bp === null) throw new Error(`breakpoint #${index} doesn't exist`);

    Bps.checkOverlaps(bp);

    bp.disable();
    bp.address = addr;
    bp.hits = hits ?? -1;
    bp.length = length === null ? 0 : length.toU64().toNumber();

    Output.writeln(`Modified ${bp.toString()}`);
    this.editBreakpoint(bp, conditional);

    return Var.fromId(index);
  }

  protected override usageCreate(): string {
    const usage: string = `
${this.name} 0 0 - create ${this.bpType} breakpoint without assigning an address

${this.name} addr len - create ${this.bpType} breakpoint without a hit limit
   addr    the address to create the breakpoint
   len     the length of the memory region to watch

${this.name} addr len hits - create ${this.bpType} breakpoint
   addr    the address to create the breakpoint
   len     the length of the memory region to watch
   hits    the number of times the breakpoint should fire

${this.name} addr len hits ${TypedBpCmdLet.CONDITIONAL_CHAR} - create ${this.bpType} breakpoint with conditions
   addr    the address to create the breakpoint
   len     the length of the memory region to watch
   hits    the number of times the breakpoint should fire`;
    return usage;
  }

  protected override usageModify(): string {
    const usage: string = `
${this.name} ${CmdLetBase.NUM_CHAR}n addr len - modify a ${this.bpType} breakpoint without a hit limit
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   len     the length of the memory region to watch

${this.name} ${CmdLetBase.NUM_CHAR}n addr len hits - modify a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   len     the length of the memory region to watch
   hits    the number of times the breakpoint should fire

${this.name} ${CmdLetBase.NUM_CHAR}n addr len hits ${TypedBpCmdLet.CONDITIONAL_CHAR} - modify a ${this.bpType} breakpoint with conditions
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to modify
   addr    the address to move the breakpoint
   len     the length of the memory region to watch
   hits    the number of times the breakpoint should fire`;
    return usage;
  }
}

export class ReadBpCmdLet extends MemoryBpCmdLet {
  name = '@r';
  bpType = BpType.MemoryRead;
  help = `${this.bpType} breakpoint`;
}

export class WriteBpCmdLet extends MemoryBpCmdLet {
  name = '@w';
  bpType = BpType.MemoryWrite;
  help = `${this.bpType} breakpoint`;
}
