import { Bp, BpKind, BpType } from './bp.js';
import { Var } from '../vars/var.js';

export class Bps {
  private static byIndex: Map<string, Bp> = new Map<string, Bp>();
  private static last: Bp | null = null;
  private static lines: string[] = [];

  private constructor() {}

  public static create(
    type: BpType,
    hits: number = -1,
    addr: Var | null = null,
    literal: string | null = null,
    length: number = 0,
  ): Bp {
    const idx = this.getNextFreeIndex(type);
    const key = this.buildKey(type, idx);

    if (addr !== null) {
      this.checkOverlaps(type, addr.toPointer(), length);
    }

    const bp = new Bp(type, idx, hits, addr, literal, length);
    this.byIndex.set(key, bp);
    this.last = bp;
    this.lines = [];
    return bp;
  }

  private static checkOverlaps(
    type: BpType,
    addr: NativePointer,
    length: number,
  ): void {
    const overlapping = Array.from(this.byIndex.values()).some(
      bp => bp.overlaps(addr, length) && Bps.conflicts(type, bp.type),
    );

    if (overlapping) {
      throw new Error(
        `breakpoint overlaps existing breakpoint:\n\t${overlapping}`,
      );
    }
  }

  private static conflicts(type1: BpType, type2: BpType): boolean {
    const kind1 = Bp.getBpKind(type1);
    const kind2 = Bp.getBpKind(type2);
    return kind1 === BpKind.Memory || kind2 === BpKind.Memory;
  }

  private static getNextFreeIndex(type: BpType): number {
    let idx = 1;
    while (true) {
      const key = this.buildKey(type, idx);
      if (!this.byIndex.has(key)) return idx;
      idx++;
    }
  }

  private static buildKey(type: BpType, index: number): string {
    return `${type}:${index.toString()}`;
  }

  public static modify(
    type: BpType,
    idx: number,
    hits: number,
    addr: Var | null = null,
    literal: string | null = null,
    length: number = 0,
  ): Bp {
    const key = this.buildKey(type, idx);

    if (!this.byIndex.has(key))
      throw new Error(`breakpoint #${idx} doesn't exist`);

    const bp = this.byIndex.get(key) as Bp;

    if (addr !== null) {
      this.checkOverlaps(type, addr.toPointer(), length);
    }

    bp.disable();
    bp.hits = hits;
    bp.address = addr;
    bp.literal = literal;
    bp.length = length;
    this.last = bp;
    this.lines = [];
    return bp;
  }

  public static get(type: BpType, idx: number): Bp | null {
    const key = this.buildKey(type, idx);
    return this.byIndex.get(key) ?? null;
  }

  public static delete(type: BpType, idx: number): Bp {
    const key = this.buildKey(type, idx);

    if (!this.byIndex.has(key))
      throw new Error(`breakpoint #${idx} doesn't exist`);

    const bp = this.byIndex.get(key) as Bp;
    this.byIndex.delete(key);
    bp.disable();
    return bp;
  }

  public static addCommandLine(line: string) {
    this.lines.push(line);
  }

  public static done() {
    if (this.last === null) throw new Error('no breakpoint to modify');
    this.last.lines = this.lines;
    this.last.enable();
    this.last = null;
  }

  public static abort() {
    if (this.last === null) throw new Error('no breakpoint to modify');
    this.last.enable();
    this.last = null;
  }

  public static all(): Bp[] {
    const items: Bp[] = Array.from(this.byIndex.values()).sort((b1, b2) =>
      b1.compare(b2),
    );
    return items;
  }
}
