import { Bp, BpKind, BpType } from './bp.js';

export class Bps {
  private static byIndex: Map<string, Bp> = new Map<string, Bp>();

  private constructor() {}

  public static add(bp: Bp) {
    const idx = this.getNextFreeIndex(bp.type);
    const key = this.buildKey(bp.type, idx);

    this.checkOverlaps(bp);
    this.byIndex.set(key, bp);
  }

  public static checkOverlaps(bp: Bp): void {
    const overlapping = Array.from(this.byIndex.values()).some(
      b =>
        b.overlaps(bp) && (b.kind !== BpKind.Code || bp.kind !== BpKind.Code),
    );

    if (overlapping) {
      throw new Error(
        `breakpoint overlaps existing breakpoint:\n\t`,
      );
    }
  }

  public static getNextFreeIndex(type: BpType): number {
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
