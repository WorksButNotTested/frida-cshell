import { Output } from './output.js';
import { Util } from './util.js';
import { Var } from './var.js';

class Bp {
  private readonly literal: string;
  private addr: Var;
  private lines: string[] = [];
  private count: number = 0;

  public constructor(addr: Var, literal: string, count: number) {
    this.addr = addr;
    this.literal = literal;
    this.count = count;
  }

  public setCount(count: number) {
    this.count = count;
  }

  public setLines(lines: string[]) {
    this.lines = lines;
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
    const addr = Output.bold(Util.toHexString(this.addr.toPointer()));
    const literal = Output.bold(this.literal);
    const hits = `[hits:${this.countString()}]`;
    const header = `${addr}: ${literal} ${hits}`;
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

  public static add(addr: Var, literal: string, count: number) {
    let bp = this.map.get(addr.toString());
    if (bp === undefined) {
      bp = new Bp(addr, literal, count);
      this.map.set(addr.toString(), bp);
    } else {
      bp.setCount(count);
    }

    this.last = bp;
    this.lines = [];
  }

  public static done() {
    if (this.last === undefined) throw new Error('No breakpoint to modify');
    this.last.setLines(this.lines);
  }

  public static abort() {}

  public static addCommandLine(line: string) {
    this.lines.push(line);
  }

  public static get(addr: Var): Bp | undefined {
    return this.map.get(addr.toString());
  }

  public static delete(addr: Var): Bp | undefined {
    const val = this.map.get(addr.toString());
    if (val === undefined) return undefined;
    this.map.delete(addr.toString());
    return val;
  }

  public static all(): Bp[] {
    const items: Bp[] = Array.from(this.map.values()).sort((b1, b2) =>
      b1.compare(b2),
    );
    return items;
  }
}
