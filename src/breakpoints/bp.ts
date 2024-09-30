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
  private readonly _type: BpType;
  private readonly _idx: number;

  private _hits: number;
  private _addr: Var | null;
  private _length: number;
  private _depth: number;
  private _conditional: boolean;

  private _commands: string[] = [];
  private _conditions: string[] = [];
  private _listener: InvocationListener | null;
  private _overlay: string | null = null;
  private _trace: Trace | null = null;

  public constructor(
    type: BpType,
    idx: number,
    hits: number,
    addr: Var | null,
    length: number = 0,
    depth: number = 0,
    conditional: boolean = false,
  ) {
    this._type = type;
    this._idx = idx;
    this._hits = hits;
    this._addr = addr;
    this._length = length;
    this._depth = depth;
    this._conditional = conditional;
    this._listener = null;
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
    return Bp.getBpKind(this._type);
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
    if (this._addr === null) return;
    if (this._listener !== null) return;
    this._overlay = Overlay.add(this._addr.toPointer(), Bp.BP_LENGTH);
    const addr = this._addr;
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bp = this;
    switch (this._type) {
      case BpType.Instruction:
        this._listener = Interceptor.attach(
          addr.toPointer(),
          function (this: InvocationContext, _args: InvocationArguments) {
            bp.breakCode(this.threadId, this.context, this.returnAddress);
          },
        );
        break;
      case BpType.FunctionEntry:
        this._listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            bp.breakCode(this.threadId, this.context, this.returnAddress);
          },
        });
        break;
      case BpType.FunctionExit:
        this._listener = Interceptor.attach(addr.toPointer(), {
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
        this._listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp._hits === 0) return;
            bp._trace = BlockTrace.create(this.threadId, bp._depth, false);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp._hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      case BpType.CallTrace:
        this._listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp._hits === 0) return;
            bp._trace = CallTrace.create(this.threadId, bp._depth);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp._hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      case BpType.UniqueBlockTrace:
        this._listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp._hits === 0) return;
            bp._trace = BlockTrace.create(this.threadId, bp._depth, true);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp._hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      case BpType.Coverage:
        this._listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            if (bp._hits === 0) return;
            bp._trace = CoverageTrace.create(this.threadId, null, null);
            bp.startCoverage(this.threadId, this.context);
          },
          onLeave(_retVal) {
            if (bp._hits === 0) return;
            bp.stopCoverage(this.threadId, this.context);
          },
        });
        break;
      default:
        throw new Error(`unknown code breakpoint type: ${this._type}`);
    }

    Interceptor.flush();
  }

  private startCoverage(threadId: ThreadId, ctx: CpuContext) {
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.writeln(
      [
        `${Output.yellow('|')} Start Trace`,
        Output.green(`#${this._idx}`),
        `[${this._type}]`,
        Output.yellow(this.literal),
        `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
        `$tid=${threadId}, depth=${this._depth}`,
      ].join(' '),
    );
    Output.writeln(Output.yellow('-'.repeat(80)));
  }

  private stopCoverage(threadId: ThreadId, ctx: CpuContext) {
    this._hits--;
    try {
      if (this._trace === null) return;
      this._trace.stop();

      Output.clearLine();
      Output.writeln(Output.blue('-'.repeat(80)));
      Output.writeln(
        [
          `${Output.yellow('|')} Stop Trace`,
          Output.green(`#${this._idx}`),
          `[${this._type}]`,
          Output.yellow(this.literal),
          `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
          `$tid=${threadId}, depth=${this._depth}`,
        ].join(' '),
      );
      Output.writeln(Output.yellow('-'.repeat(80)));

      const data = this._trace.data();
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
    if (this._hits === 0) return;

    Regs.setThreadId(threadId);
    Regs.setContext(ctx);
    Regs.setReturnAddress(returnAddress);
    if (retVal !== null) Regs.setRetVal(retVal);

    try {
      if (this.runConditions()) {
        if (this._hits > 0) this._hits--;
        Output.clearLine();
        Output.writeln(Output.yellow('-'.repeat(80)));
        Output.writeln(
          [
            `${Output.yellow('|')} Break`,
            Output.green(`#${this._idx}`),
            `[${this._type}]`,
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
    if (!this._conditional) return true;
    if (this._conditions.length === 0) return true;

    if (!Output.getDebugging()) {
      Output.suppress(true);
    }
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      for (const condition of this._conditions) {
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
      for (const command of this._commands) {
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
    if (this._listener === null) return;
    this._listener.detach();
    this._listener = null;
    Interceptor.flush();
    if (this._overlay === null) return;
    Overlay.remove(this._overlay);
  }

  public breakMemory(details: MemoryAccessDetails) {
    switch (details.operation) {
      case 'read':
        if (this._type !== BpType.MemoryRead) return;
        break;
      case 'write':
        if (this._type !== BpType.MemoryWrite) return;
        break;
      case 'execute':
        return;
    }

    if (this._hits === 0) return;

    Regs.setAddress(details.address);
    Regs.setPc(details.from);

    try {
      if (this.runConditions()) {
        if (this._hits > 0) this._hits--;

        Output.clearLine();
        Output.writeln(Output.yellow('-'.repeat(80)));
        Output.writeln(
          [
            `${Output.yellow('|')} Break`,
            Output.green(`#${this._idx}`),
            `[${this._type}]`,
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
    if (this._addr === null) return false;
    if (this._length === 0) return false;

    const start = this._addr.toPointer();

    if (start.add(this._length).compare(address) <= 0) return false;
    if (start.compare(address.add(length)) >= 0) return false;
    return true;
  }

  public compare(other: Bp): number {
    return this._idx - other._idx;
  }

  public toString(): string {
    const idxString = Output.green(`#${this._idx.toString()}.`.padEnd(4, ' '));
    const typeString = `[${this._type.toString()}]`;
    const literalString = Output.yellow(this.literal);
    const addString = `@ $pc=${Output.blue(this.addrString)}`;
    const hitsString = `[hits:${this.hitsString}]`;
    const lengthString = this.lengthString;
    const conditionalString = Output.blue(
      this._conditional ? 'conditional' : 'unconditional',
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

    if (this._conditional && this._conditions.length !== 0) {
      lines.push(Output.green('Conditions:'));
      this._conditions.forEach(c => {
        lines.push(`  - ${Output.yellow(c)}`);
      });
    }

    if (this._commands.length !== 0) {
      lines.push(Output.green('Commands:'));
      this._commands.forEach(c => {
        lines.push(`  - ${Output.yellow(c)}`);
      });
    }

    return `${lines.join('\n')}\n`;
  }

  private get addrString(): string {
    if (this._addr === null) return 'unassigned';

    const p = this._addr.toPointer();
    return Format.toHexString(p);
  }

  private get hitsString(): string {
    if (this._hits < 0) {
      return 'unlimited';
    } else if (this._hits === 0) {
      return 'disabled';
    } else {
      return this._hits.toString();
    }
  }

  private get lengthString(): string {
    if (this.kind === BpKind.Code) return '';
    else return `[length:${this._length}]`;
  }

  public get type(): BpType {
    return this._type;
  }

  public get index(): number {
    return this._idx;
  }

  public get address(): Var | null {
    return this._addr;
  }

  public get literal(): string {
    return this._addr?.getLiteral() ?? '';
  }

  public get length(): number | null {
    return this._length;
  }

  public get depth(): number | null {
    return this._depth;
  }

  public get hits(): number {
    return this._hits;
  }

  public get conditional(): boolean {
    return this._conditional;
  }

  public get conditions(): string[] {
    return this._conditions;
  }

  public get commands(): string[] {
    return this._commands;
  }

  public set address(addr: Var | null) {
    if (addr === null) return;
    this._addr = addr;
  }

  public set length(length: number | null) {
    if (length === null) return;
    this._length = length;
  }

  public set depth(depth: number | null) {
    if (depth === null) return;
    this._depth = depth;
  }

  public set conditional(conditional: boolean | null) {
    if (conditional === null) return;
    this._conditional = conditional;
  }

  public set hits(hits: number) {
    this._hits = hits;
  }

  public set commands(commands: string[]) {
    this._commands = commands;
  }

  public set conditions(conditions: string[]) {
    this._conditions = conditions;
  }
}
