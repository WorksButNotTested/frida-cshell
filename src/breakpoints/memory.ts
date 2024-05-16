import { Mem } from '../memory/mem.js';
import { Bp, BpType } from './bp.js';

class MemoryCallbacks implements MemoryAccessCallbacks {
  onAccess = function (details: MemoryAccessDetails) {
    const idx = details.rangeIndex;
    const bps = MemoryBps.getActiveBps();

    if (idx >= bps.length)
      throw new Error(`failed to find memory breakpoint idx: ${idx}`);

    const bp = bps[idx] as Bp;
    bp.breakMemory(details);
    MemoryBps.refresh();
  };
}

export class MemoryBps {
  private static callbacks = new MemoryCallbacks();
  private static memoryBps: Map<string, Bp> = new Map<string, Bp>();

  private static buildKey(type: BpType, index: number): string {
    return `${type}:${index.toString()}`;
  }

  public static enableBp(bp: Bp) {
    const key = this.buildKey(bp.type, bp.index);
    this.memoryBps.set(key, bp);
    this.refresh();
  }

  public static disableBp(bp: Bp) {
    const key = this.buildKey(bp.type, bp.index);
    this.memoryBps.delete(key);
    this.refresh();
  }

  public static getActiveBps(): Bp[] {
    const bps = Array.from(this.memoryBps.values());
    return bps
      .filter(bp => bp.address !== null)
      .filter(bp => bp.length !== null)
      .filter(bp => bp.length !== 0)
      .filter(bp => bp.hits !== 0);
  }

  public static disable() {
    MemoryAccessMonitor.disable();
  }

  public static enable() {
    const bps = this.getActiveBps();

    const ranges = Array.from(
      bps.map(bp => {
        return {
          base: bp.address?.toPointer() as NativePointer,
          size: bp.length,
        } as MemoryAccessRange;
      }),
    );

    if (ranges.length === 0) return;
    MemoryAccessMonitor.enable(ranges, this.callbacks);
  }

  public static refresh() {
    this.disable();
    this.enable();
  }

  public static containsAddress(address: NativePointer): boolean {
    const aligned = Mem.pageAlignDown(address);
    const bps = this.getActiveBps();
    return bps.some(b => b.overlaps(aligned, Process.pageSize));
  }
}
