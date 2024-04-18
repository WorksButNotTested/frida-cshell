import { Util } from '../util.js';
import { Bp, BpType } from './bp.js';

class MemoryCallbacks implements MemoryAccessCallbacks {
  onAccess = function (details: MemoryAccessDetails) {
    const idx = details.rangeIndex;
    const bps = MemoryBps.getActiveBps();
    const bp = bps[idx];
    if (bp === undefined)
      throw new Error(`Failed to find memory breakpoint idx: ${idx}`);
    bp.breakMemory(details);
    MemoryBps.refreshMemoryBps();
  };
}

export class MemoryBps {
  private static callbacks = new MemoryCallbacks();
  private static memoryBps: Map<string, Bp> = new Map<string, Bp>();

  private static buildKey(type: BpType, index: number): string {
    return `${type}:${index.toString()}`;
  }

  public static enableMemoryBp(bp: Bp) {
    const key = this.buildKey(bp.type, bp.index);
    this.memoryBps.set(key, bp);
    this.refreshMemoryBps();
  }

  public static disableMemoryBp(bp: Bp) {
    const key = this.buildKey(bp.type, bp.index);
    this.memoryBps.delete(key);
    this.refreshMemoryBps();
  }

  public static getActiveBps(): Bp[] {
    const bps = Array.from(this.memoryBps.values());
    return bps
      .filter(bp => bp.address?.toPointer() !== undefined)
      .filter(bp => bp.length !== undefined)
      .filter(bp => bp.length !== 0)
      .filter(bp => bp.hits !== 0);
  }

  public static refreshMemoryBps() {
    MemoryAccessMonitor.disable();
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

  public static containsAddress(address: NativePointer): boolean {
    const aligned = Util.pageAlignDown(address);
    const bps = this.getActiveBps();
    return bps.some(b => b.overlaps(aligned, Process.pageSize));
  }
}
