export enum MemProtection {
  PROT_NONE = 0,
  PROT_READ = 0x1,
  PROT_WRITE = 0x2,
  PROT_READ_WRITE = PROT_READ | PROT_WRITE,
}

export class Mem {
  private static readonly MAP_PRIVATE: number = 0x2;
  private static readonly MAP_ANONYMOUS: number = 0x20;

  private static readonly MAP_FAILED: NativePointer = ptr(-1);

  /* void *mmap(void addr[.length], size_t length, int prot, int flags,
                  int fd, off_t offset); */
  private fnMmap: SystemFunction<
    NativePointer,
    [NativePointer, number | UInt64, number, number, number, number | UInt64]
  >;

  /* int mprotect(void addr[.len], size_t len, int prot); */
  private fnMprotect: SystemFunction<
    number,
    [NativePointer, number | UInt64, number]
  >;

  public constructor() {
    const pMmap = Module.findExportByName(null, 'mmap');
    if (pMmap === null) throw new Error('failed to find mmap');

    this.fnMmap = new SystemFunction(pMmap, 'pointer', [
      'pointer',
      'size_t',
      'int',
      'int',
      'int',
      'size_t',
    ]);

    const pMprotect = Module.findExportByName(null, 'mprotect');
    if (pMprotect === null) throw new Error('failed to find mprotect');

    this.fnMprotect = new SystemFunction(pMprotect, 'int', [
      'pointer',
      'size_t',
      'int',
    ]);
  }

  public map_anonymous(size: number): NativePointer {
    const ret = this.fnMmap(
      ptr(0),
      size,
      MemProtection.PROT_READ | MemProtection.PROT_WRITE,
      Mem.MAP_ANONYMOUS | Mem.MAP_PRIVATE,
      -1,
      0,
    ) as UnixSystemFunctionResult<NativePointer>;
    if (ret.value.equals(Mem.MAP_FAILED))
      throw new Error(`failed to mmap, errno: ${ret.errno}`);
    return ret.value;
  }

  public protect(addr: NativePointer, size: number, prot: MemProtection) {
    const ret = this.fnMprotect(
      addr,
      size,
      prot,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value === -1)
      throw new Error(`failed to mprotect, errno: ${ret.errno}`);
  }

  public static pageAlign(size: number): number {
    const mask = Process.pageSize - 1;
    return (size + mask) & ~mask;
  }
}
