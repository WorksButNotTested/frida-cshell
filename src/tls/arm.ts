import { Output } from '../io/output.js';

export class TlsArm {
  private static readonly SHELL_CODE: Uint8Array = new Uint8Array([
    /* mrc p15,0x0,r0,cr13,cr0,0x3 */ 0x70, 0x0f, 0x1d, 0xee, /* bx lr */ 0x1e,
    0xff, 0x2f, 0xe1,
  ]);

  public getTls(): NativePointer {
    const buffer = Memory.alloc(
      TlsArm.SHELL_CODE.length + 2 * Process.pageSize,
    );
    Output.debug(`buffer: ${buffer.toString(16)}`);
    const shellCode = buffer.add(Process.pageSize);
    Output.debug(`shellCode: ${shellCode.toString(16)}`);
    shellCode.writeByteArray(TlsArm.SHELL_CODE.buffer as ArrayBuffer);
    const fnPtr = new NativeFunction(shellCode, 'pointer', []);
    Memory.protect(shellCode, TlsArm.SHELL_CODE.length, 'r-x');
    const seg = fnPtr();
    Memory.protect(shellCode, TlsArm.SHELL_CODE.length, 'rw-');
    return seg;
  }

  public static getTls(): NativePointer {
    const tls = new TlsArm();
    const ptr = tls.getTls();
    return ptr;
  }
}
