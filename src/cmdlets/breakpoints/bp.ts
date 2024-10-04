import { Bp, BpType } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import { CmdLetBase } from '../../commands/cmdlet.js';
import { Input, InputInterceptLine } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

enum InputMode {
  Conditions = 'conditions',
  Commands = 'commands',
}

abstract class TypedBpCmdLet extends CmdLetBase implements InputInterceptLine {
  protected static readonly CONDITIONAL_CHAR: string = '?';
  public abstract readonly bpType: BpType;
  protected abstract runCreate(tokens: Token[]): Var | null;
  protected abstract runModify(tokens: Token[]): Var | null;
  protected abstract usageCreate(): string;
  protected abstract usageModify(): string;

  private last: Bp | null = null;
  private mode: InputMode = InputMode.Conditions;
  private conditions: string[] | null = [];
  private commands: string[] | null = [];

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
    const [_, [index]] = vars as [[], [number | null]];

    if (index === null) {
      Output.writeln(
        `${Output.blue(this.bpType)} ${Output.blue('breakpoints')}:`,
      );
      Bps.all()
        .filter(bp => bp.type === this.bpType)
        .forEach(bp => Output.writeln(bp.toString(), true));
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
    const usage: string = `Usage: ${this.name}
${Output.bold('show:')}

${this.name} - show all ${this.bpType} breakpoints

${this.name} ${CmdLetBase.NUM_CHAR}n - show a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to show

${Output.bold('create:')}
${create}

${Output.bold('modify:')}
${modify}

${Output.bold('delete:')}

${this.name} ${CmdLetBase.NUM_CHAR}n # - delete a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to delete

${Output.bold('NOTE:')} Set hits to '*' for unlimited breakpoint.`;

    Output.writeln(usage);
    return Var.ZERO;
  }

  protected parseConditional(token: Token): string | null {
    const literal = token.getLiteral();
    if (literal !== TypedBpCmdLet.CONDITIONAL_CHAR) return null;
    return literal;
  }

  protected newBreakpoint(bp: Bp) {
    switch (this.bpType) {
      case BpType.BlockTrace:
      case BpType.CallTrace:
      case BpType.UniqueBlockTrace:
      case BpType.Coverage:
        bp.enable();
        break;
      default:
        this.last = bp;
        if (bp.conditional) {
          this.mode = InputMode.Conditions;
          if (bp.conditions.length > 0) {
            Output.writeln(Output.bold("Breakpoint's current conditions:"));
            bp.conditions.forEach(c =>
              Output.writeln(`  - ${Output.yellow(c)}`),
            );
          } else {
            Output.writeln(
              Output.bold('Breakpoint currently has no conditions'),
            );
          }

          Output.writeln(Output.green("Enter breakpoint's conditions:"));
        } else {
          this.mode = InputMode.Commands;
          if (bp.commands.length > 0) {
            Output.writeln(Output.bold("Breakpoint's current commands:"));
            bp.commands.forEach(c => Output.writeln(`  - ${Output.yellow(c)}`));
          } else {
            Output.writeln(Output.bold('Breakpoint currently has no commands'));
          }
          Output.writeln(Output.green("Enter breakpoint's commands:"));
        }

        Input.setInterceptLine(this);
        break;
    }
  }

  startLines(): void {
    switch (this.mode) {
      case InputMode.Conditions:
        this.conditions = [];
        break;
      case InputMode.Commands:
        this.commands = [];
        break;
    }
  }

  addLine(line: string): void {
    switch (this.mode) {
      case InputMode.Conditions:
        if (this.conditions === null) return;
        this.conditions.push(line);
        break;
      case InputMode.Commands:
        if (this.commands === null) return;
        this.commands.push(line);
        break;
    }
  }

  done(): void {
    Output.writeln();
    switch (this.mode) {
      case InputMode.Conditions:
        if (this.last !== null) {
          if (this.last.commands.length > 0) {
            Output.writeln(Output.bold("Breakpoint's current commands:"));
            this.last.commands.forEach(c =>
              Output.writeln(`  - ${Output.yellow(c)}`),
            );
          } else {
            Output.writeln(Output.bold('Breakpoint currently has no commands'));
          }
        }
        Output.writeln(Output.green("Enter breakpoint's commands:"));
        this.mode = InputMode.Commands;
        Input.setInterceptLine(this);
        break;
      case InputMode.Commands:
        if (this.last !== null) {
          if (this.conditions) {
            this.last.conditions = this.conditions;
          }
          if (this.commands) {
            this.last.commands = this.commands;
          }
          this.last.enable();
        }
        break;
    }
  }

  clearLines(): void {
    switch (this.mode) {
      case InputMode.Conditions:
        this.conditions = [];
        break;
      case InputMode.Commands:
        this.commands = [];
        break;
    }
    this.done();
  }

  saveLines(): void {
    this.done();
  }

  cancelLines(): void {
    switch (this.mode) {
      case InputMode.Conditions:
        this.conditions = null;
        break;
      case InputMode.Commands:
        this.commands = null;
        break;
    }
    this.done();
  }
}

abstract class CodeBpCmdLet extends TypedBpCmdLet {
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[addr], [hits, conditional]] = vars as [
      [Var],
      [number | null, string | null],
    ];

    if (addr.isNull()) {
      const bp = Bps.create(this.bpType, 0, null, 0);
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (hits === null) {
      const bp = Bps.create(this.bpType, -1, addr, Bp.BP_LENGTH);
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (conditional === null) {
      const bp = Bps.create(this.bpType, hits, addr, Bp.BP_LENGTH);
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else {
      const bp = Bps.create(this.bpType, hits, addr, Bp.BP_LENGTH, 0, true);
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    }

    return addr;
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[index, addr], [hits, conditional]] = vars as [
      [number, Var],
      [number | null, string | null],
    ];

    if (addr.isNull()) {
      const bp = Bps.modify(this.bpType, index, 0, null, 0);
      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (hits === null) {
      const bp = Bps.modify(this.bpType, index, -1, addr, Bp.BP_LENGTH);
      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (conditional === null) {
      const bp = Bps.modify(this.bpType, index, hits, addr, Bp.BP_LENGTH);
      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else {
      const bp = Bps.modify(
        this.bpType,
        index,
        hits,
        addr,
        Bp.BP_LENGTH,
        0,
        true,
      );
      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    }

    return addr ?? Var.ZERO;
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

abstract class MemoryBpCmdLet extends TypedBpCmdLet {
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[addr, length], [hits, conditional]] = vars as [
      [Var, Var],
      [number | null, string | null],
    ];

    if (addr.isNull()) {
      const bp = Bps.create(this.bpType, 0, null, 0);
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (hits === null) {
      const bp = Bps.create(this.bpType, -1, addr, length.toU64().toNumber());
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (conditional === null) {
      const bp = Bps.create(this.bpType, hits, addr, length.toU64().toNumber());
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else {
      const bp = Bps.create(
        this.bpType,
        hits,
        addr,
        length.toU64().toNumber(),
        0,
        true,
      );
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    }
    return addr ?? Var.ZERO;
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[index, addr, length], [hits, conditional]] = vars as [
      [number, Var, Var],
      [number | null, string | null],
    ];

    if (addr.isNull()) {
      const bp = Bps.modify(this.bpType, index, 0, null, 0);
      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (hits === null) {
      const bp = Bps.modify(
        this.bpType,
        index,
        -1,
        addr,
        length.toU64().toNumber(),
      );

      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (conditional === null) {
      const bp = Bps.modify(
        this.bpType,
        index,
        hits,
        addr,
        length.toU64().toNumber(),
      );

      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else {
      const bp = Bps.modify(
        this.bpType,
        index,
        hits,
        addr,
        length.toU64().toNumber(),
        0,
        true,
      );

      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    }

    return addr ?? Var.ZERO;
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

abstract class TraceBpCmdLet extends TypedBpCmdLet {
  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[addr, depth], [hits, conditional]] = vars as [
      [Var, Var],
      [number | null, string | null],
    ];

    if (addr.isNull()) return null;

    if (hits === null) {
      const bp = Bps.create(
        this.bpType,
        -1,
        addr,
        Bp.BP_LENGTH,
        depth.toU64().toNumber(),
      );
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (conditional === null) {
      const bp = Bps.create(
        this.bpType,
        hits,
        addr,
        Bp.BP_LENGTH,
        depth.toU64().toNumber(),
      );
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else {
      const bp = Bps.create(
        this.bpType,
        hits,
        addr,
        Bp.BP_LENGTH,
        depth.toU64().toNumber(),
        true,
      );
      Output.writeln(`Created ${bp.toString()}`);
      this.newBreakpoint(bp);
    }

    return addr ?? Var.ZERO;
  }

  protected runModify(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseIndex, this.parseVar, this.parseVar],
      [this.parseNumberOrAll, this.parseConditional],
    );
    if (vars === null) return null;
    const [[index, addr, depth], [hits, conditional]] = vars as [
      [number, Var, Var],
      [number | null, string | null],
    ];

    if (addr.isNull()) return null;

    if (hits === null) {
      const bp = Bps.modify(
        this.bpType,
        index,
        -1,
        addr,
        Bp.BP_LENGTH,
        depth.toU64().toNumber(),
      );

      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else if (conditional === null) {
      const bp = Bps.modify(
        this.bpType,
        index,
        hits,
        addr,
        Bp.BP_LENGTH,
        depth.toU64().toNumber(),
      );

      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    } else {
      const bp = Bps.modify(
        this.bpType,
        index,
        hits,
        addr,
        Bp.BP_LENGTH,
        depth.toU64().toNumber(),
        true,
      );

      Output.writeln(`Modified ${bp.toString()}`);
      this.newBreakpoint(bp);
    }

    return addr ?? Var.ZERO;
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
}
