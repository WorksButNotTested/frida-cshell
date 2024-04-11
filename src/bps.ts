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

class Bp {
  private readonly type: BpType;
  private readonly addr: Var;
  private readonly literal: string;

  private count: number = 0;

  private lines: string[] = [];
  private listener: InvocationListener;
  private enabled: boolean = false;

  public constructor(type: BpType, addr: Var, literal: string, count: number) {
    this.type = type;
    this.addr = addr;
    this.literal = literal;
    this.count = count;

    switch (this.type) {
      case BpType.Instruction:
        this.listener = Interceptor.attach(
          addr.toPointer(),
          function (this: InvocationContext, args: InvocationArguments) {
            Bps.break(addr, this.threadId, this.context, this.returnAddress);
          },
        );
        break;
      case BpType.FunctionEntry:
        this.listener = Interceptor.attach(addr.toPointer(), {
          onEnter() {
            Bps.break(addr, this.threadId, this.context, this.returnAddress);
          },
        })
        break;
      case BpType.FunctionExit:
        throw new Error('TODO');
    }
    
    Interceptor.flush();
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
    this.enabled = false;
  }

  public enable() {
    this.enabled = true;
  }

  public detach() {
    this.listener.detach();
  }

  public break(
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
  ) {
    if (!this.enabled) return;
    if (this.count == 0) return;
    else if (this.count > 0) this.count--;
    Output.clearLine();
    Output.writeln(`Break @ ${Util.toHexString(this.addr.toPointer())}`);
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

  public toString(): string {
    const type = this.type.toString();
    const addr = Output.bold(Util.toHexString(this.addr.toPointer()));
    const literal = Output.bold(this.literal);
    const hits = `[hits:${this.countString()}]`;
    const header = `${type} ${addr}: ${literal} ${hits}`;
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

  public static add(type: BpType, addr: Var, literal: string, count: number) {
    let bp = this.map.get(addr.toString());
    if (bp === undefined) {
      bp = new Bp(type, addr, literal, count);
      this.map.set(addr.toString(), bp);
    } else if (bp.getType() == type) {
      /* If it is the same type, then we will modify in place */
      bp.disable();
      bp.setCount(count);
    } else {
      /* If it is a different type then we will start anew */
      bp.detach();
      bp = new Bp(type, addr, literal, count);
      this.map.set(addr.toString(), bp);
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

  public static get(addr: Var): Bp | undefined {
    return this.map.get(addr.toString());
  }

  public static delete(addr: Var): Bp | undefined {
    const val = this.map.get(addr.toString());
    if (val === undefined) return undefined;
    this.map.delete(addr.toString());
    val.detach();
    return val;
  }

  public static all(): Bp[] {
    const items: Bp[] = Array.from(this.map.values()).sort((b1, b2) =>
      b1.compare(b2),
    );
    return items;
  }

  public static break(
    addr: Var,
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
  ) {
    const bp = this.get(addr);
    if (bp === undefined)
      throw new Error(
        `Hit breakpoint not found at ${Util.toHexString(addr.toPointer())}`,
      );
    bp.break(threadId, ctx, returnAddress);
  }
}
