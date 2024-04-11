import { Output } from './output.js';
import { Var } from './var.js';

class Bp {
  private readonly literal: string;
  private lines: string[] = [];

  public constructor(literal: string) {
    this.literal = literal;
  }

  public setLines(lines: string[]) {
    this.lines = lines;
  }

  public toString(): string {
    return (
      `${Output.bold(this.literal)}\n` +
      this.lines.map(l => `  - ${Output.yellow(l)}`).join('\n') +
      '\n'
    );
  }
}

export class Bps {
  private static map: Map<string, Bp> = new Map<string, Bp>();
  private static last: Bp | undefined = undefined;
  private static lines: string[] = [];

  private constructor() {}

  public static add(addr: Var, literal: string) {
    let bp = this.map.get(addr.toString());
    if (bp === undefined) {
      bp = new Bp(literal);
      this.map.set(addr.toString(), bp);
    }

    this.last = bp;
    this.lines = [];
  }

  public static done(): void {
    if (this.last === undefined) throw new Error('No breakpoint to modify');
    this.last.setLines(this.lines);
  }

  public static abort(): void {}

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

  public static all(): [Var, Bp][] {
    const items: [string, Bp][] = Array.from(this.map.entries());
    const vars: [Var, Bp][] = items.map(([k, v]) => [new Var(k), v]);
    const ret = vars.sort(([k1, _v1], [k2, _v2]) =>
      k1.toPointer().compare(k2.toPointer()),
    );
    return ret;
  }
}
