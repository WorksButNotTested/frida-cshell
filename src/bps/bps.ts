import { Bp, BpType } from './bp.js';
import { Var } from '../var.js';

export class Bps {
  private static byIndex: Map<string, Bp> = new Map<string, Bp>();
  private static last: Bp | undefined = undefined;
  private static lines: string[] = [];

  private constructor() {}

  private static buildKey(type: BpType, index: number): string {
    return `${type}:${index.toString()}`;
  }

  private static getNextFreeIndex(type: BpType): number {
    let idx = 1;
    while (true) {
      const key = this.buildKey(type, idx);
      if (!this.byIndex.has(key)) return idx;
      idx++;
    }
  }

  public static create(
    type: BpType,
    hits: number = -1,
    addr: Var | undefined = undefined,
    literal: string | undefined = undefined,
    length: number = 0,
  ): Bp {
    const idx = this.getNextFreeIndex(type);
    const key = this.buildKey(type, idx);

    const overlapping = Array.from(this.byIndex.values()).find(bp =>
      bp.overlaps(addr?.toPointer(), length),
    );

    if (overlapping !== undefined)
      throw new Error(
        `Breakpoint overlaps existing breakpoint:\n\t${overlapping}`,
      );

    const bp = new Bp(type, idx, hits, addr, literal, length);
    this.byIndex.set(key, bp);
    this.last = bp;
    this.lines = [];
    return bp;
  }

  public static get(type: BpType, idx: number): Bp | undefined {
    const key = this.buildKey(type, idx);
    return this.byIndex.get(key);
  }

  public static modify(
    type: BpType,
    idx: number,
    hits: number,
    addr: Var | undefined = undefined,
    literal: string | undefined = undefined,
    length: number = 0,
  ): Bp {
    const key = this.buildKey(type, idx);
    const bp = this.byIndex.get(key);
    if (bp === undefined) throw new Error(`Breakpoint #${idx} doesn't exist`);

    const overlapping = Array.from(this.byIndex.values())
      .filter(b => b !== bp)
      .find(b => b.overlaps(addr?.toPointer(), length));

    if (overlapping !== undefined)
      throw new Error(
        `Breakpoint overlaps existing breakpoint:\n\t${overlapping}`,
      );

    bp.disable();
    bp.hits = hits;
    bp.address = addr;
    bp.literal = literal;
    bp.length = length;
    this.last = bp;
    this.lines = [];
    return bp;
  }

  public static delete(type: BpType, idx: number): Bp {
    const key = this.buildKey(type, idx);
    const bp = this.byIndex.get(key);
    if (bp === undefined) throw new Error(`Breakpoint #${idx} doesn't exist`);
    this.byIndex.delete(key);
    bp.disable();
    return bp;
  }

  public static addCommandLine(line: string) {
    this.lines.push(line);
  }

  public static done() {
    if (this.last === undefined) throw new Error('No breakpoint to modify');
    this.last.lines = this.lines;
    this.last.enable();
    this.last = undefined;
  }

  public static abort() {
    if (this.last === undefined) throw new Error('No breakpoint to modify');
    this.last.enable();
    this.last = undefined;
  }

  public static all(): Bp[] {
    const items: Bp[] = Array.from(this.byIndex.values()).sort((b1, b2) =>
      b1.compare(b2),
    );
    return items;
  }
}