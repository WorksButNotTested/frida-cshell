export class TlsX64 {
  private static readonly ARCH_GET_FS: number = 0x1003;
  private readonly arch_prctl: SystemFunction<number, [number, NativePointer]>;

  constructor() {
    const pArchPrctl = Module.findExportByName(null, 'arch_prctl');
    if (pArchPrctl === null) throw new Error('failed to find arch_prctl');
    this.arch_prctl = new SystemFunction(pArchPrctl, 'int', ['int', 'pointer']);
  }

  public getTls(): NativePointer {
    const tls = Memory.alloc(Process.pointerSize);

    const ret = this.arch_prctl(
      TlsX64.ARCH_GET_FS,
      tls,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value !== 0)
      throw new Error(`arch_prctl failed, errno: ${ret.errno}`);

    return tls.readPointer();
  }

  public static getTls(): NativePointer {
    const tls = new TlsX64();
    const ptr = tls.getTls();
    return ptr;
  }
}
