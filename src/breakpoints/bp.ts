import { Command } from '../commands/command.js';
import { Input } from '../io/input.js';
import { MemoryBps } from './memory.js';
import { Output } from '../io/output.js';
import { Overlay } from '../memory/overlay.js';
import { Parser } from '../io/parser.js';
import { Regs } from './regs.js';
import { Format } from '../misc/format.js';
import { BlockTrace } from '../traces/block.js';
import { Trace, Traces } from '../traces/trace.js';
import { Var } from '../vars/var.js';
import { Vars } from '../vars/vars.js';
import { CallTrace } from '../traces/call.js';
import { CoverageTrace } from '../traces/coverage/trace.js';

export const BP_LENGTH: number = 16;

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
  private readonly _type: BpType;
  private readonly _idx: number;

  private _hits: number;
  private _addr: Var | null;
  private _length: number;
  private _depth: number;

  private _lines: string[] = [];
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
  ) {
    this._type = type;
    this._idx = idx;
    this._hits = hits;
    this._addr = addr;
    this._length = length;
    this._depth = depth;
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
    this._overlay = Overlay.add(this._addr.toPointer(), BP_LENGTH);
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
            bp._trace = BlockTrace.create(this.threadId, bp._depth);
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
            bp._trace = CoverageTrace.create(this.threadId);
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
    Output.write(`${Output.yellow('|')} Start Trace `);
    Output.write(`${Output.green(`#${this._idx}`)} `);
    Output.write(`[${this._type}] `);
    Output.write(`${Output.yellow(this.literal)} `);
    Output.write(`@ $pc=${Output.blue(Format.toHexString(ctx.pc))} `);
    Output.write(`$tid=${threadId}, depth=${this._depth}`);
    Output.writeln();
    Output.writeln(Output.yellow('-'.repeat(80)));
  }

  private stopCoverage(threadId: ThreadId, ctx: CpuContext) {
    this._hits--;
    try {
      if (this._trace === null) return;
      this._trace.stop();

      Output.writeln(Output.blue('-'.repeat(80)));
      this._trace.display();
      Output.writeln(Output.blue('-'.repeat(80)));
      Output.clearLine();

      Output.writeln(Output.yellow('-'.repeat(80)));
      Output.write(`${Output.yellow('|')} Stop Trace `);
      Output.write(`${Output.green(`#${this._idx}`)} `);
      Output.write(`[${this._type}] `);
      Output.write(`${Output.yellow(this.literal)} `);
      Output.write(`@ $pc=${Output.blue(Format.toHexString(ctx.pc))} `);
      Output.write(`$tid=${threadId}`);
      Output.writeln();
      Output.writeln(Output.yellow('-'.repeat(80)));

      Traces.delete(threadId);
    } finally {
      Input.prompt();
      Regs.clear();
    }
  }

  private breakCode(
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
    retVal: InvocationReturnValue | null = null,
  ) {
    if (this._hits === 0) return;
    else if (this._hits > 0) this._hits--;
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.write(`${Output.yellow('|')} Break `);
    Output.write(`${Output.green(`#${this._idx}`)} `);
    Output.write(`[${this._type}] `);
    Output.write(`${Output.yellow(this.literal)} `);
    Output.write(`@ $pc=${Output.blue(Format.toHexString(ctx.pc))} `);
    Output.write(`$tid=${threadId}`);
    Output.writeln();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Regs.setThreadId(threadId);
    Regs.setContext(ctx);
    Regs.setReturnAddress(returnAddress);

    if (retVal !== null) Regs.setRetVal(retVal);

    this.runCommands();
  }

  private runCommands() {
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      for (const line of this._lines) {
        if (line.length === 0) continue;
        if (line.charAt(0) === '#') continue;
        Output.writeln(`${Output.bold(Input.PROMPT)}${line}`);
        const parser = new Parser(line.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } catch (error) {
      if (error instanceof Error) {
        Output.writeln(`ERROR: ${error.message}`);
        Output.writeln(`${error.stack}`, true);
      } else {
        Output.writeln(`ERROR: Unknown error`);
      }
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Output.writeln(Output.yellow('-'.repeat(80)));
      Input.prompt();
      Regs.clear();
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
    else if (this._hits > 0) this._hits--;

    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.write(`${Output.yellow('|')} Break `);
    Output.write(`${Output.green(`#${this._idx}`)} `);
    Output.write(`[${this._type}] `);
    Output.write(`${Output.yellow(this.literal)} `);
    Output.write(`@ $pc=${Output.blue(Format.toHexString(details.from))} `);
    Output.write(`$addr=${Output.blue(Format.toHexString(details.address))}`);
    Output.writeln();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Regs.setAddress(details.address);
    Regs.setPc(details.from);

    this.runCommands();
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
    const header = [
      idxString,
      typeString,
      literalString,
      addString,
      hitsString,
      lengthString,
    ].join(' ');

    const lines = this._lines.map(l => `  - ${Output.yellow(l)}`);
    lines.unshift(header);
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

  public set hits(hits: number) {
    this._hits = hits;
  }

  public set lines(lines: string[]) {
    this._lines = lines;
  }
}
