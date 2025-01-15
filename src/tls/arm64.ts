export class TlsAarch64 {
  private static readonly SHELL_CODE: Uint8Array = new Uint8Array([
    /* mrs x0, tpidr_el0 */ 0x40, 0xd0, 0x3b, 0xd5, /* ret */ 0xc0, 0x03, 0x5f,
    0xd6,
  ]);

  private readonly code: NativePointer;
  private readonly fn: NativeFunction<NativePointer, []>;

  public constructor() {
    this.code = Memory.alloc(Process.pageSize);
    this.code.writeByteArray(TlsAarch64.SHELL_CODE.buffer as ArrayBuffer);
    Memory.protect(this.code, Process.pageSize, 'r-x');
    this.fn = new NativeFunction(this.code, 'pointer', []);
  }

  public getTls(): NativePointer {
    const seg = this.fn();
    return seg;
  }

  public static getTls(): NativePointer {
    const tls = new TlsAarch64();
    const ptr = tls.getTls();
    return ptr;
  }
}
