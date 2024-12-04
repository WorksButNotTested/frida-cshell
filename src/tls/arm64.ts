import { Output } from '../io/output.js';

export class TlsAarch64 {
  private static readonly SHELL_CODE: Uint8Array = new Uint8Array([
    /* mrs x0, tpidr_el0 */ 0x40, 0xd0, 0x3b, 0xd5, /* ret */ 0xc0, 0x03, 0x5f,
    0xd6,
  ]);

  public getTls(): NativePointer {
    const buffer = Memory.alloc(
      TlsAarch64.SHELL_CODE.length + 2 * Process.pageSize,
    );
    Output.debug(`buffer: ${buffer.toString(16)}`);
    const shellCode = buffer.add(Process.pageSize);
    Output.debug(`shellCode: ${shellCode.toString(16)}`);
    shellCode.writeByteArray(TlsAarch64.SHELL_CODE.buffer as ArrayBuffer);
    const fnPtr = new NativeFunction(shellCode, 'pointer', []);
    Memory.protect(shellCode, TlsAarch64.SHELL_CODE.length, 'r-x');
    const seg = fnPtr();
    Memory.protect(shellCode, TlsAarch64.SHELL_CODE.length, 'rw-');
    return seg;
  }

  public static getTls(): NativePointer {
    const tls = new TlsAarch64();
    const ptr = tls.getTls();
    return ptr;
  }
}
