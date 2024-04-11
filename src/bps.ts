import { Command } from './command.js';
import { Output } from './output.js';
import { Parser } from './parser.js';
import { Regs } from './regs.js';
import { Util } from './util.js';
import { Var } from './var.js';
import { Vars } from './vars.js';

export enum BpType {
  Instruction = 'instruction',
  FunctionEntry = 'function entry',
  FunctionExit = 'function exit',
}

export class Bp {
  private readonly type: BpType;
  private readonly addr: Var;
  private readonly literal: string;

  private count: number = 0;

  private lines: string[] = [];
  private listener: InvocationListener | undefined;

  public constructor(type: BpType, addr: Var, literal: string, count: number) {
    this.type = type;
    this.addr = addr;
    this.literal = literal;
    this.count = count;
    this.listener = undefined;
  }

  public getType(): BpType {
    return this.type;
  }

  public setCount(count: number) {
    this.count = count;
  }

  public setLines(lines: string[]) {
    this.lines = lines;
  }

  public disable() {
    if (this.listener === undefined) return;
    this.listener.detach();
    this.listener = undefined;
  }

  public enable() {
    if (this.listener !== undefined) return;
    const addr = this.addr;
    switch (this.type) {
      case BpType.Instruction:
        this.listener = Interceptor.attach(
          addr.toPointer(),
          function (this: InvocationContext, _args: InvocationArguments) {
            Bps.break(
              BpType.Instruction,
              addr,
              this.threadId,
              this.context,
              this.returnAddress,
            );
          },
        );
        break;
      case BpType.FunctionEntry:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            Bps.break(
              BpType.FunctionEntry,
              addr,
              this.threadId,
              this.context,
              this.returnAddress,
            );
          },
        });
        break;
      case BpType.FunctionExit:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onLeave() {
            Bps.break(
              BpType.FunctionExit,
              addr,
              this.threadId,
              this.context,
              this.returnAddress,
            );
          },
        });
        break;
    }

    Interceptor.flush();
  }

  public break(
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
  ) {
    if (this.count == 0) return;
    else if (this.count > 0) this.count--;
    Output.clearLine();
    Output.writeln(`Break [${this.type}] @ ${Util.toHexString(ctx.pc)}`);
    Output.writeln();
    Regs.setThreadId(threadId);
    Regs.setContext(ctx);
    Regs.setReturnAddress(returnAddress);
    try {
      for (const line of this.lines) {
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
    }
    Output.writeRet();
    Output.prompt();

    Regs.clear();
  }

  private countString(): string {
    if (this.count < 0) {
      return 'unlimited';
    } else if (this.count == 0) {
      return 'disabled';
    } else {
      return this.count.toString();
    }
  }

  public compare(other: Bp): number {
    return this.addr.compare(other.addr);
  }

  public toString(short: boolean = false): string {
    const type = this.type.toString();
    const addr = Output.bold(Util.toHexString(this.addr.toPointer()));
    const literal = Output.bold(this.literal);
    const hits = `[hits:${this.countString()}]`;
    const header = `${short ? '' : type} ${addr}: ${literal} ${hits}`;
    const lines = this.lines.map(l => `  - ${Output.yellow(l)}`);
    lines.unshift(header);
    return `${lines.join('\n')}\n`;
  }
}

export class Bps {
  private static map: Map<string, Bp> = new Map<string, Bp>();
  private static last: Bp | undefined = undefined;
  private static lines: string[] = [];

  private constructor() {}

  private static buildKey(type: BpType, addr: Var): string {
    return `${type}:${addr.toPointer().toString()}`;
  }

  public static add(type: BpType, addr: Var, literal: string, count: number) {
    const key = this.buildKey(type, addr);
    let bp = this.map.get(key);
    if (bp === undefined) {
      bp = new Bp(type, addr, literal, count);
      this.map.set(key, bp);
    } else {
      bp.disable();
      bp.setCount(count);
    }

    this.last = bp;
    this.lines = [];
  }

  public static addCommandLine(line: string) {
    this.lines.push(line);
  }

  public static done() {
    if (this.last === undefined) throw new Error('No breakpoint to modify');
    this.last.setLines(this.lines);
    this.last.enable();
  }

  public static abort() {
    if (this.last === undefined) throw new Error('No breakpoint to modify');
    this.last.enable();
  }

  public static get(type: BpType, addr: Var): Bp | undefined {
    const key = this.buildKey(type, addr);
    return this.map.get(key);
  }

  public static delete(type: BpType, addr: Var): Bp | undefined {
    const key = this.buildKey(type, addr);
    const bp = this.map.get(key);
    if (bp === undefined) return undefined;
    this.map.delete(key);
    bp.disable();
    return bp;
  }

  public static all(): Bp[] {
    const items: Bp[] = Array.from(this.map.values()).sort((b1, b2) =>
      b1.compare(b2),
    );
    return items;
  }

  public static break(
    type: BpType,
    addr: Var,
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
  ) {
    const bp = this.get(type, addr);
    if (bp === undefined)
      throw new Error(
        `Hit breakpoint not found at ${Util.toHexString(addr.toPointer())}`,
      );
    bp.break(threadId, ctx, returnAddress);
  }
}
