import { Command } from '../command.js';
import { Input } from '../input.js';
import { MemoryBps } from './memory.js';
import { Output } from '../output.js';
import { Overlay } from '../overlay.js';
import { Parser } from '../parser.js';
import { Regs } from '../regs.js';
import { Util } from '../util.js';
import { Var } from '../var.js';
import { Vars } from '../vars.js';

const BP_LENGTH: number = 16;

export enum BpKind {
  Code = 'code',
  Memory = 'memory',
}

export enum BpType {
  Instruction = 'instruction',
  FunctionEntry = 'function entry',
  FunctionExit = 'function exit',
  MemoryRead = 'memory read',
  MemoryWrite = 'memory write',
}

export class Bp {
  private readonly _type: BpType;
  private readonly _idx: number;

  private _hits: number;
  private _addr: Var | undefined;
  private _literal: string | undefined;
  private _length: number;

  private _lines: string[] = [];
  private _listener: InvocationListener | undefined;
  private _overlay: string | undefined = undefined;

  public constructor(
    type: BpType,
    idx: number,
    hits: number,
    addr: Var | undefined,
    literal: string | undefined,
    length: number = 0,
  ) {
    this._type = type;
    this._idx = idx;
    this._hits = hits;
    this._addr = addr;
    this._literal = literal;
    this._length = length;
    this._listener = undefined;
  }

  public get type(): BpType {
    return this._type;
  }

  public get index(): number {
    return this._idx;
  }

  public get address(): Var | undefined {
    return this._addr;
  }

  public get length(): number | undefined {
    return this._length;
  }

  public get hits(): number {
    return this._hits;
  }

  public set address(addr: Var | undefined) {
    if (addr === undefined) return;
    this._addr = addr;
  }

  public set literal(literal: string | undefined) {
    if (literal === undefined) return;
    this._literal = literal;
  }

  public set length(length: number | undefined) {
    if (length === undefined) return;
    this._length = length;
  }

  public set hits(hits: number) {
    this._hits = hits;
  }

  public set lines(lines: string[]) {
    this._lines = lines;
  }

  public static getBpKind(type: BpType): BpKind {
    switch (type) {
      case BpType.Instruction:
      case BpType.FunctionEntry:
      case BpType.FunctionExit:
        return BpKind.Code;
        break;
      case BpType.MemoryRead:
      case BpType.MemoryWrite:
        return BpKind.Memory;
    }
  }

  private get kind(): BpKind {
    return Bp.getBpKind(this._type);
  }

  public enable() {
    switch (this.kind) {
      case BpKind.Code:
        this.enableCode();
        break;
      case BpKind.Memory:
        MemoryBps.enableMemoryBp(this);
        break;
    }
  }

  public disable() {
    switch (this.kind) {
      case BpKind.Code:
        this.disableCode();
        break;
      case BpKind.Memory:
        MemoryBps.disableMemoryBp(this);
        break;
    }
  }

  public disableCode() {
    if (this._listener === undefined) return;
    this._listener.detach();
    this._listener = undefined;
    Interceptor.flush();
    if (this._overlay === undefined) return;
    Overlay.remove(this._overlay);
  }

  private enableCode() {
    if (this._addr === undefined) return;
    if (this._listener !== undefined) return;
    this._overlay = Overlay.add(this._addr.toPointer(), BP_LENGTH);
    const addr = this._addr;
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
    }

    Interceptor.flush();
  }

  private runCommands() {
    Input.suppressEdit(true);
    try {
      for (const line of this._lines) {
        const parser = new Parser(line.toString());
        const tokens = parser.tokenize();
        const ret = Command.run(tokens);
        Vars.setRet(ret);
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
      Input.suppressEdit(false);
      Output.writeRet();
      Input.prompt();
      Regs.clear();
    }
  }

  private breakCode(
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
    retVal: InvocationReturnValue | undefined = undefined,
  ) {
    if (this._hits == 0) return;
    else if (this._hits > 0) this._hits--;
    Output.clearLine();
    Output.writeln(
      `Break #${this._idx} [${this._type}] @ $pc=${Util.toHexString(ctx.pc)}, $tid=${threadId}`,
    );
    Output.writeln();
    Regs.setThreadId(threadId);
    Regs.setContext(ctx);
    Regs.setReturnAddress(returnAddress);

    if (retVal !== undefined) Regs.setRetVal(retVal);

    this.runCommands();
  }

  public breakMemory(details: MemoryAccessDetails) {
    switch (details.operation) {
      case 'read':
        if (this._type != BpType.MemoryRead) return;
        break;
      case 'write':
        if (this._type != BpType.MemoryWrite) return;
        break;
      case 'execute':
        return;
    }

    if (this._hits == 0) return;
    else if (this._hits > 0) this._hits--;

    Output.clearLine();
    Output.writeln(
      `Break #${this._idx} [${this._type}] @ $pc=${Util.toHexString(details.from)}, $addr=${Util.toHexString(details.address)}`,
    );
    Output.writeln();
    Regs.setAddress(details.address);
    Regs.setPc(details.from);

    this.runCommands();
  }

  public overlaps(
    address: NativePointer | undefined,
    length: number | undefined,
  ): boolean {
    if (address === undefined) return false;
    if (length === undefined) return false;

    const start = this._addr?.toPointer();
    if (start === undefined) return false;

    if (this._length === 0) return false;

    if (start.add(this._length).compare(address) <= 0) return false;
    if (start.compare(address.add(length)) >= 0) return false;
    return true;
  }

  private get hitsString(): string {
    if (this._hits < 0) {
      return 'unlimited';
    } else if (this._hits == 0) {
      return 'disabled';
    } else {
      return this._hits.toString();
    }
  }

  private get addrString(): string {
    const p = this._addr?.toPointer();
    if (p !== undefined) {
      return Util.toHexString(p);
    } else {
      return 'unassigned';
    }
  }

  private get lengthString(): string {
    if (this.kind == BpKind.Code) return '';
    else return `[length:${this._length}]`;
  }

  public compare(other: Bp): number {
    return this._idx - other._idx;
  }

  public toString(short: boolean = false): string {
    const type = this._type.toString();
    const addr = Output.bold(this.addrString);
    const literal = Output.bold(this._literal ?? '');
    const hits = `[hits:${this.hitsString}]`;
    const header = `#${this._idx.toString().padEnd(3, ' ')}. ${short ? '' : type} ${addr}: ${literal} ${hits} ${this.lengthString}`;
    const lines = this._lines.map(l => `  - ${Output.yellow(l)}`);
    lines.unshift(header);
    return `${lines.join('\n')}\n`;
  }
}
