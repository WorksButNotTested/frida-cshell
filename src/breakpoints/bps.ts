import { Bp, BpKind, BpType } from './bp.js';
import { Var } from '../vars/var.js';

export class Bps {
  private static byIndex: Map<string, Bp> = new Map<string, Bp>();

  private constructor() {}

  public static create(
    type: BpType,
    hits: number = -1,
    addr: Var | null = null,
    length: number = 0,
    depth: number = 0,
    conditional: boolean = false,
  ): Bp {
    const idx = this.getNextFreeIndex(type);
    const key = this.buildKey(type, idx);

    if (addr !== null) {
      this.checkOverlaps(type, addr.toPointer(), length);
    }

    const bp = new Bp(type, idx, hits, addr, length, depth, conditional);
    this.byIndex.set(key, bp);
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
    length: number = 0,
    depth: number = 0,
    conditional: boolean = false,
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
    bp.length = length;
    bp.depth = depth;
    bp.conditional = conditional;
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

  public static all(): Bp[] {
    const items: Bp[] = Array.from(this.byIndex.values()).sort((b1, b2) =>
      b1.compare(b2),
    );
    return items;
  }
}
