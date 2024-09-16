import { BP_LENGTH, BpType } from '../breakpoints/bp.js';
import { Bps } from '../breakpoints/bps.js';
import { CmdLet } from '../commands/cmdlet.js';
import { Input, InputInterceptLine } from '../io/input.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const NUM_CHAR: string = '#';
const UNLIMITED_CHAR: string = '*';

abstract class TypedBpCmdLet extends CmdLet implements InputInterceptLine {
  public abstract readonly bpType: BpType;
  protected abstract runCreate(tokens: Token[]): Var | null;
  protected abstract runModify(tokens: Token[]): Var | null;
  protected abstract usageCreate(): string;
  protected abstract usageModify(): string;

  category = 'breakpoints';

  public runSync(tokens: Token[]): Var {
    const retModify = this.runModify(tokens);
    if (retModify !== null) return retModify;

    const retCreate = this.runCreate(tokens);
    if (retCreate !== null) return retCreate;

    const retShow = this.runShow(tokens);
    if (retShow !== null) return retShow;

    const retDelete = this.runDelete(tokens);
    if (retDelete !== null) return retDelete;

    return this.usage();
  }

  protected parseIndex(token: Token): number | null {
    const literal = token.getLiteral();
    if (!literal.startsWith(NUM_CHAR)) return null;

    const numStr = literal.slice(1);
    const val = parseInt(numStr);

    if (isNaN(val)) return null;
    return val;
  }

  protected parseHits(token: Token): number | null {
    if (token.getLiteral() === UNLIMITED_CHAR) return -1;

    const v = token.toVar();
    if (v === null) return null;

    const hits = v.toU64().toNumber();
    return hits;
  }

  private runDelete(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseIndex, this.parseDelete]);
    if (vars === null) return null;
    const [index, _] = vars as [number, string];

    const bp = Bps.delete(this.bpType, index);
    Output.writeln(`Deleted ${bp.toString()}`);
    return bp.address ?? Var.ZERO;
  }

  private runShow(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseIndex]);
    if (vars === null) return null;
    const [[], [index]] = vars as [[], [number | null]];

    if (index === null) {
      Output.writeln(
        `${Output.blue(this.bpType)} ${Output.blue('breakpoints')}:`,
      );
      Bps.all()
        .filter(bp => bp.type === this.bpType)
        .forEach(bp => Output.writeln(bp.toString(true)));
      return Var.ZERO;
    } else {
      const bp = Bps.get(this.bpType, index);
      if (bp === null) throw new Error(`breakpoint #${index} not found`);

      Output.writeln(bp.toString());
      return bp.address;
    }
  }

  public usage(): Var {
    const create = this.usageCreate();
    const modify = this.usageModify();
    const INSN_BP_USAGE: string = `Usage: ${this.name}
${Output.bold('show:')}

${this.name} - show all ${this.bpType} breakpoints

${this.name} ${NUM_CHAR}n - show a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to show

${Output.bold('create:')}
${create}

${Output.bold('modify:')}
${modify}

${Output.bold('delete:')}

${this.name} ${NUM_CHAR}n # - delete a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to delete

${Output.bold('NOTE:')} Set hits to '*' for unlimited breakpoint.
`;
    Output.write(INSN_BP_USAGE);
    return Var.ZERO;
  }

  addLine(line: string) {
    Bps.addCommandLine(line);
  }

  done() {
    Bps.done();
  }

  abort() {
    Bps.abort();
  }
}

abstract class CodeBpCmdLet
  extends TypedBpCmdLet
  implements InputInterceptLine
{
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseHits],
      [this.parseVar],
    );
    if (vars === null) return null;
    const [[hits], [addr]] = vars as [[number], [Var | null]];

    const bp = Bps.create(
      this.bpType,
      hits,
      addr,
      addr === null ? 0 : BP_LENGTH,
    );
    Output.writeln(`Created ${bp.toString()}`);
    this.addCommands();
    return addr ?? Var.ZERO;
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseHits],
      [this.parseVar],
    );
    if (vars === null) return null;
    const [[index, hits], [addr]] = vars as [[number, number], [Var | null]];

    const bp = Bps.modify(
      this.bpType,
      index,
      hits,
      addr,
      addr === null ? 0 : BP_LENGTH,
    );
    Output.writeln(`Modified ${bp.toString()}`);
    this.addCommands();
    return addr ?? Var.ZERO;
  }

  protected addCommands(): void {
    Input.setInterceptLine(this);
  }

  protected override usageCreate(): string {
    const USAGE: string = `
${this.name} hits - create ${this.bpType} breakpoint without assigning an address
   hits    the number of times the breakpoint should fire

${this.name} hits addr - create ${this.bpType} breakpoint
   hits    the number of times the breakpoint should fire
   addr    the address to create the breakpoint`;

    return USAGE;
  }

  protected override usageModify(): string {
    const USAGE: string = `
${this.name} ${NUM_CHAR}n hits - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire

${this.name} ${NUM_CHAR}n hits addr - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire
   addr    the address to move the breakpoint`;
    return USAGE;
  }
}

abstract class MemoryBpCmdLet
  extends TypedBpCmdLet
  implements InputInterceptLine
{
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseHits],
      [this.parseVar, this.parseVar],
    );
    if (vars === null) return null;
    const [[hits], [addr, length]] = vars as [
      [number],
      [Var | null, Var | null],
    ];
    if (addr !== null && length === null) return null;
    const bp = Bps.create(
      this.bpType,
      hits,
      addr,
      length === null ? 0 : length.toU64().toNumber(),
    );

    Output.writeln(`Created ${bp.toString()}`);
    Input.setInterceptLine(this);
    return addr ?? Var.ZERO;
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseHits],
      [this.parseVar, this.parseVar],
    );
    if (vars === null) return null;
    const [[index, hits], [addr, length]] = vars as [
      [number, number],
      [Var | null, Var | null],
    ];

    if (addr !== null && length === null) return null;

    const bp = Bps.modify(
      this.bpType,
      index,
      hits,
      addr,
      length === null ? 0 : length.toU64().toNumber(),
    );

    Output.writeln(`Modified ${bp.toString()}`);
    Input.setInterceptLine(this);
    return addr ?? Var.ZERO;
  }

  protected override usageCreate(): string {
    const USAGE: string = `
${this.name} hits - create ${this.bpType} breakpoint without assigning an address
   hits    the number of times the breakpoint should fire

${this.name} hits addr len - create ${this.bpType} breakpoint
   hits    the number of times the breakpoint should fire
   addr    the address to create the breakpoint
   len     the length of the memory region to watch`;
    return USAGE;
  }

  protected override usageModify(): string {
    const USAGE: string = `
${this.name} ${NUM_CHAR}n hits - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire

${this.name} ${NUM_CHAR}n hits addr len - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire
   addr    the address to move the breakpoint
   len     the length of the memory region to watch`;
    return USAGE;
  }
}

abstract class TraceBpCmdLet
  extends TypedBpCmdLet
  implements InputInterceptLine
{
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseHits],
      [this.parseVar, this.parseVar],
    );
    if (vars === null) return null;
    const [[hits], [addr, depth]] = vars as [
      [number],
      [Var | null, Var | null],
    ];
    if (addr !== null && depth === null) return null;
    const bp = Bps.create(
      this.bpType,
      hits,
      addr,
      BP_LENGTH,
      depth === null ? 0 : depth.toU64().toNumber(),
    );

    Output.writeln(`Created ${bp.toString()}`);
    this.done();
    return addr ?? Var.ZERO;
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseHits],
      [this.parseVar, this.parseVar],
    );
    if (vars === null) return null;
    const [[index, hits], [addr, depth]] = vars as [
      [number, number],
      [Var, Var],
    ];

    if (addr !== null && depth === null) return null;

    const bp = Bps.modify(
      this.bpType,
      index,
      hits,
      addr,
      BP_LENGTH,
      depth === null ? 0 : depth.toU64().toNumber(),
    );

    Output.writeln(`Modified ${bp.toString()}`);
    this.done();
    return addr ?? Var.ZERO;
  }

  protected override usageCreate(): string {
    const USAGE: string = `
${this.name} hits - create ${this.bpType} breakpoint without assigning an address
   hits    the number of times the breakpoint should fire

${this.name} hits addr depth - create ${this.bpType} breakpoint
   hits    the number of times the breakpoint should fire
   addr    the address to create the breakpoint
   depth   the maximum depth of callstack to follow`;
    return USAGE;
  }

  protected override usageModify(): string {
    const USAGE: string = `
${this.name} ${NUM_CHAR}n hits - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire

${this.name} ${NUM_CHAR}n hits addr depth - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire
   addr    the address to move the breakpoint
   depth   the maximum depth of callstack to follow`;
    return USAGE;
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

export class CoverageBpCmdLet extends CodeBpCmdLet {
  name = '@c';
  bpType = BpType.Coverage;
  help = `${this.bpType} breakpoint`;

  protected override addCommands(): void {
    this.done();
  }
}
