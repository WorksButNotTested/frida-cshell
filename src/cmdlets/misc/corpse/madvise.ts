import { Mem } from '../../../memory/mem.js';

export class Madvise {
  private static readonly MADV_DOFORK: number = 11;
  private static readonly MADV_DODUMP: number = 17;
  // int madvise(void addr[.length], size_t length, int advice);
  private fnMadvise: SystemFunction<
    number,
    [NativePointer, UInt64 | number, number]
  >;

  constructor() {
    const pMadvise = Module.findExportByName(null, 'madvise');
    if (pMadvise === null) throw new Error('failed to find madvise');

    this.fnMadvise = new SystemFunction(pMadvise, 'int', [
      'pointer',
      'size_t',
      'int',
    ]);
  }

  private doFork(base: NativePointer, size: number) {
    const ret = this.fnMadvise(
      base,
      size,
      Madvise.MADV_DOFORK,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value !== 0)
      throw new Error(
        `failed to madvise, errno: ${ret.errno}, base: ${base}, size: ${size}`,
      );
  }

  private doDump(base: NativePointer, size: number) {
    const ret = this.fnMadvise(
      base,
      size,
      Madvise.MADV_DODUMP,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value !== 0)
      throw new Error(
        `failed to madvise, errno: ${ret.errno}, base: ${base}, size: ${size}`,
      );
  }

  private alignRange(
    base: NativePointer,
    size: number,
  ): { base: NativePointer; size: number } {
    const limit = base.add(size);
    const alignedLimit = Mem.pageAlignUp(limit);
    const alignedBase = Mem.pageAlignDown(base);
    const alignedSize = alignedLimit.sub(alignedBase).toUInt32();
    return { base: alignedBase, size: alignedSize };
  }

  private forAlignedRanges(fn: (base: NativePointer, size: number) => void) {
    Process.enumerateRanges('---').forEach(r => {
      const { base, size } = this.alignRange(r.base, r.size);
      fn(base, size);
    });
  }

  public tryForkAll(debug: (msg: string) => void) {
    this.forAlignedRanges((base, size) => {
      try {
        this.doFork(base, size);
      } catch (e) {
        debug(
          `failed to madvise MADV_DOFORK range: ${e}, base: ${base}, size: ${size}`,
        );
      }
    });
  }

  public tryDumpAll(debug: (msg: string) => void) {
    this.forAlignedRanges((base, size) => {
      try {
        this.doDump(base, size);
      } catch (e) {
        debug(
          `failed to madvise MADV_DODUMP range: ${e}, base: ${base}, size: ${size}`,
        );
      }
    });
  }
}
