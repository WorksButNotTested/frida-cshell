import { Command } from '../commands/command.js';
import { Input } from '../io/input.js';
import { MemoryBps } from './memory.js';
import { Output } from '../io/output.js';
import { Overlay } from '../memory/overlay.js';
import { Parser } from '../io/parser.js';
import { Regs } from './regs.js';
import { Format } from '../misc/format.js';
import { BlockTrace } from '../traces/block.js';
import { Trace, TraceData, Traces } from '../traces/trace.js';
import { Var } from '../vars/var.js';
import { Vars } from '../vars/vars.js';
import { CallTrace } from '../traces/call.js';
import { CoverageTrace } from '../traces/coverage/trace.js';

export enum BpKind {
  Code = 'code',
  Memory = 'memory',
}

export enum BpType {
  Instruction = 'instruction',
  FunctionEntry = 'function entry',
  FunctionExit = 'function exit',
  BlockTrace = 'block trace',
  CallTrace = 'call trace',
  UniqueBlockTrace = 'unique block trace',
  Coverage = 'coverage',
  MemoryRead = 'memory read',
  MemoryWrite = 'memory write',
}

export class Bp {
  public static readonly BP_LENGTH: number = 16;

  public readonly type: BpType;
  public readonly index: number;

  public hits: number;
  public address: Var | null;
  public length: number;
  public depth: number;
  public conditional: boolean;
  public conditions: string[] = [];
  public commands: string[] = [];

  private listener: InvocationListener | null;
  private overlay: string | null = null;
  private trace: Trace | null = null;

  public constructor(
    type: BpType,
    idx: number,
    hits: number,
    addr: Var | null,
    length: number = 0,
    depth: number = 0,
    conditional: boolean = false,
  ) {
    this.type = type;
    this.index = idx;
    this.hits = hits;
    this.address = addr;
    this.length = length;
    this.depth = depth;
    this.conditional = conditional;
    this.listener = null;
  }

  public enable() {
    switch (this.kind) {
      case BpKind.Code:
        this.enableCode();
        break;
      case BpKind.Memory:
        MemoryBps.enableBp(this);
        break;
    }
  }

  private get kind(): BpKind {
    return Bp.getBpKind(this.type);
  }

  public static getBpKind(type: BpType): BpKind {
    switch (type) {
      case BpType.Instruction:
      case BpType.FunctionEntry:
      case BpType.FunctionExit:
      case BpType.BlockTrace:
      case BpType.CallTrace:
      case BpType.UniqueBlockTrace:
      case BpType.Coverage:
        return BpKind.Code;
      case BpType.MemoryRead:
      case BpType.MemoryWrite:
        return BpKind.Memory;
    }
  }

  private enableCode() {
    if (this.address === null) return;
    if (this.listener !== null) return;
    this.overlay = Overlay.add(this.address.toPointer(), Bp.BP_LENGTH);
    const addr = this.address;
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bp = this;
    switch (this.type) {
      case BpType.Instruction:
        this.listener = Interceptor.attach(
          addr.toPointer(),
          function (this: InvocationContext, _args: InvocationArguments) {
            bp.breakCode(this.threadId, this.context, this.returnAddress);
          },
        );
        break;
      case BpType.FunctionEntry:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            bp.breakCode(this.threadId, this.context, this.returnAddress);
          },
        });
        break;
      case BpType.FunctionExit:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onLeave(retVal) {
            bp.breakCode(
              this.threadId,
              this.context,
              this.returnAddress,
              retVal,
            );
          },
        });
        break;
      case BpType.BlockTrace:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp.hits === 0) return;
            bp.trace = BlockTrace.create(this.threadId, bp.depth, false);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp.hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      case BpType.CallTrace:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp.hits === 0) return;
            bp.trace = CallTrace.create(this.threadId, bp.depth);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp.hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      case BpType.UniqueBlockTrace:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp.hits === 0) return;
            bp.trace = BlockTrace.create(this.threadId, bp.depth, true);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp.hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      case BpType.Coverage:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp.hits === 0) return;
            bp.trace = CoverageTrace.create(this.threadId, null, null);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp.hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      default:
        throw new Error(`unknown code breakpoint type: ${this.type}`);
    }

    Interceptor.flush();
  }

  private startCoverage(threadId: ThreadId, ctx: CpuContext) {
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.writeln(
      [
        `${Output.yellow('|')} Start Trace`,
        Output.green(`#${this.index}`),
        `[${this.type}]`,
        Output.yellow(this.literal),
        `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
        `$tid=${threadId}, depth=${this.depth}`,
      ].join(' '),
    );
    Output.writeln(Output.yellow('-'.repeat(80)));
  }

  private stopCoverage(threadId: ThreadId, ctx: CpuContext) {
    this.hits--;
    try {
      if (this.trace === null) return;
      this.trace.stop();

      Output.clearLine();
      Output.writeln(Output.blue('-'.repeat(80)));
      Output.writeln(
        [
          `${Output.yellow('|')} Stop Trace`,
          Output.green(`#${this.index}`),
          `[${this.type}]`,
          Output.yellow(this.literal),
          `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
          `$tid=${threadId}, depth=${this.depth}`,
        ].join(' '),
      );
      Output.writeln(Output.yellow('-'.repeat(80)));

      const data = this.trace.data();
      setTimeout(() => this.displayTraceData(data));

      Traces.delete(threadId);
    } finally {
      Input.prompt();
      Regs.clear();
    }
  }

  private displayTraceData(trace: TraceData) {
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.writeln(`${Output.yellow('|')} Displaying trace:`);
    Output.writeln(Output.yellow('-'.repeat(80)));
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      trace
        .lines()
        .slice(0, TraceData.MAX_LINES)
        .forEach(l => {
          Output.writeln(l);
        });
      Output.writeln();
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Output.writeln(Output.yellow('-'.repeat(80)));
      Input.prompt();
    }
  }

  private breakCode(
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
    retVal: InvocationReturnValue | null = null,
  ) {
    if (this.hits === 0) return;

    Regs.setThreadId(threadId);
    Regs.setContext(ctx);
    Regs.setReturnAddress(returnAddress);
    if (retVal !== null) Regs.setRetVal(retVal);

    try {
      if (this.runConditions()) {
        if (this.hits > 0) this.hits--;
        Output.clearLine();
        Output.writeln(Output.yellow('-'.repeat(80)));
        Output.writeln(
          [
            `${Output.yellow('|')} Break`,
            Output.green(`#${this.index}`),
            `[${this.type}]`,
            Output.yellow(this.literal),
            `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
            `$tid=${threadId}`,
          ].join(' '),
        );
        Output.writeln(Output.yellow('-'.repeat(80)));
        this.runCommands();
      }
    } finally {
      Regs.clear();
    }
  }

  private runConditions(): boolean {
    if (!this.conditional) return true;
    if (this.conditions.length === 0) return true;

    if (!Output.getDebugging()) {
      Output.suppress(true);
    }
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      for (const condition of this.conditions) {
        if (condition.length === 0) continue;
        if (condition.charAt(0) === '#') continue;
        Output.writeln(`${Output.bold(Input.PROMPT)}${condition}`);
        const parser = new Parser(condition.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Input.prompt();
      Output.suppress(false);
    }

    if (Vars.getRet().compare(Var.ZERO) === 0) {
      return false;
    } else {
      return true;
    }
  }

  private runCommands() {
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      for (const command of this.commands) {
        if (command.length === 0) continue;
        if (command.charAt(0) === '#') continue;
        Output.writeln(`${Output.bold(Input.PROMPT)}${command}`);
        const parser = new Parser(command.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } catch (error) {
      if (error instanceof Error) {
        Output.writeln(`ERROR: ${error.message}`);
        Output.debug(`${error.stack}`);
      } else {
        Output.writeln(`ERROR: Unknown error`);
      }
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Output.writeln(Output.yellow('-'.repeat(80)));
      Input.prompt();
    }
  }

  public disable() {
    switch (this.kind) {
      case BpKind.Code:
        this.disableCode();
        break;
      case BpKind.Memory:
        MemoryBps.disableBp(this);
        break;
    }
  }

  public disableCode() {
    if (this.listener === null) return;
    this.listener.detach();
    this.listener = null;
    Interceptor.flush();
    if (this.overlay === null) return;
    Overlay.remove(this.overlay);
  }

  public breakMemory(details: MemoryAccessDetails) {
    switch (details.operation) {
      case 'read':
        if (this.type !== BpType.MemoryRead) return;
        break;
      case 'write':
        if (this.type !== BpType.MemoryWrite) return;
        break;
      case 'execute':
        return;
    }

    if (this.hits === 0) return;

    Regs.setAddress(details.address);
    Regs.setPc(details.from);

    try {
      if (this.runConditions()) {
        if (this.hits > 0) this.hits--;

        Output.clearLine();
        Output.writeln(Output.yellow('-'.repeat(80)));
        Output.writeln(
          [
            `${Output.yellow('|')} Break`,
            Output.green(`#${this.index}`),
            `[${this.type}]`,
            Output.yellow(this.literal),
            `@ $pc=${Output.blue(Format.toHexString(details.from))}`,
            `$addr=${Output.blue(Format.toHexString(details.address))}`,
          ].join(' '),
        );
        Output.writeln(Output.yellow('-'.repeat(80)));

        this.runCommands();
      }
    } finally {
      Regs.clear();
    }
  }

  public overlaps(
    address: NativePointer | null,
    length: number | null,
  ): boolean {
    if (address === null) return false;
    if (length === null) return false;
    if (this.address === null) return false;
    if (this.length === 0) return false;

    const start = this.address.toPointer();

    if (start.add(this.length).compare(address) <= 0) return false;
    if (start.compare(address.add(length)) >= 0) return false;
    return true;
  }

  public compare(other: Bp): number {
    return this.index - other.index;
  }

  public toString(): string {
    const idxString = Output.green(`#${this.index.toString()}.`.padEnd(4, ' '));
    const typeString = `[${this.type.toString()}]`;
    const literalString = Output.yellow(this.literal);
    const addString = `@ $pc=${Output.blue(this.addrString)}`;
    const hitsString = `[hits:${this.hitsString}]`;
    const lengthString = this.lengthString;
    const conditionalString = Output.blue(
      this.conditional ? 'conditional' : 'unconditional',
    );
    const header = [
      idxString,
      typeString,
      literalString,
      addString,
      hitsString,
      lengthString,
      conditionalString,
    ].join(' ');

    const lines = [header];

    if (this.conditional && this.conditions.length !== 0) {
      lines.push(Output.green('Conditions:'));
      this.conditions.forEach(c => {
        lines.push(`  - ${Output.yellow(c)}`);
      });
    }

    if (this.commands.length !== 0) {
      lines.push(Output.green('Commands:'));
      this.commands.forEach(c => {
        lines.push(`  - ${Output.yellow(c)}`);
      });
    }

    return `${lines.join('\n')}\n`;
  }

  private get addrString(): string {
    if (this.address === null) return 'unassigned';

    const p = this.address.toPointer();
    return Format.toHexString(p);
  }

  private get hitsString(): string {
    if (this.hits < 0) {
      return 'unlimited';
    } else if (this.hits === 0) {
      return 'disabled';
    } else {
      return this.hits.toString();
    }
  }

  private get lengthString(): string {
    if (this.kind === BpKind.Code) return '';
    else return `[length:${this.length}]`;
  }

  private get literal(): string {
    return this.address?.getLiteral() ?? '';
  }
}
