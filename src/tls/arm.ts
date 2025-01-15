export class TlsArm {
  private static readonly SHELL_CODE: Uint8Array = new Uint8Array([
    /* mrc p15,0x0,r0,cr13,cr0,0x3 */ 0x70, 0x0f, 0x1d, 0xee, /* bx lr */ 0x1e,
    0xff, 0x2f, 0xe1,
  ]);

  private readonly code: NativePointer;
  private readonly fn: NativeFunction<NativePointer, []>;

  public constructor() {
    this.code = Memory.alloc(Process.pageSize);
    this.code.writeByteArray(TlsArm.SHELL_CODE.buffer as ArrayBuffer);
    Memory.protect(this.code, Process.pageSize, 'r-x');
    this.fn = new NativeFunction(this.code, 'pointer', []);
  }

  public getTls(): NativePointer {
    const seg = this.fn();
    return seg;
  }

  public static getTls(): NativePointer {
    const tls = new TlsArm();
    const ptr = tls.getTls();
    return ptr;
  }
}
