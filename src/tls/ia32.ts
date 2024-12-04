import { Output } from '../io/output.js';

class Selector {
  private readonly value: number;

  constructor(value: number) {
    this.value = value;
  }

  public getRpl(): number {
    return this.value & 0x3;
  }

  public getTi(): number {
    return (this.value >> 2) & 0x1;
  }

  public getIndex(): number {
    return (this.value >> 3) & 0x1fff;
  }

  public toString(): string {
    return [
      `RPL ${this.getRpl()}`,
      `TI ${this.getTi()}`,
      `INDEX ${this.getIndex()}`,
    ].join(' ');
  }
}

/*
 * entry_number: int,
 * base: void*
 * limit: void*
 * flags: int
 */
class ThreadArea {
  private static readonly INT_SIZE = 4;
  private static readonly SIZE: number =
    Process.pointerSize * 2 + ThreadArea.INT_SIZE * 2;
  private readonly buff: NativePointer;

  constructor(segment: Selector) {
    this.buff = Memory.alloc(ThreadArea.SIZE);
    this.buff.writeInt(segment.getIndex());
  }

  public ptr(): NativePointer {
    return this.buff;
  }

  public getBase(): NativePointer {
    return this.buff.add(Process.pointerSize).readPointer();
  }

  public getLimit(): NativePointer {
    return this.buff.add(Process.pointerSize * 2).readPointer();
  }

  public getFlags(): number {
    return this.buff.add(Process.pointerSize * 3).readInt();
  }

  public toString(): string {
    return [
      `IDX: ${this.buff.readInt()}`,
      `BASE: ${this.getBase().toString(16)}`,
      `LIMIT: ${this.getLimit().toString(16)}`,
      `FLAGS: ${this.getFlags().toString(16)}`,
    ].join(' ');
  }
}

export class TlsIa32 {
  private static readonly SYS_get_thread_area: number = 0xf4;
  private fnSyscall: SystemFunction<number, [number | UInt64, NativePointer]>;

  private static readonly SHELL_CODE: Uint8Array = new Uint8Array([
    /* xor eax, eax */ 0x31, 0xc0, /* mov ax, gs */ 0x66, 0x8c, 0xe8,
    /* ret */ 0xc3,
  ]);

  constructor() {
    const pSyscall = Module.findExportByName(null, 'syscall');
    if (pSyscall === null) throw new Error('failed to find syscall');

    this.fnSyscall = new SystemFunction(pSyscall, 'int', ['size_t', 'pointer']);
  }

  public getSegment(): Selector {
    const buffer = Memory.alloc(
      TlsIa32.SHELL_CODE.length + 2 * Process.pageSize,
    );
    Output.debug(`buffer: ${buffer.toString(16)}`);
    const shellCode = buffer.add(Process.pageSize);
    Output.debug(`shellCode: ${shellCode.toString(16)}`);
    shellCode.writeByteArray(TlsIa32.SHELL_CODE.buffer as ArrayBuffer);
    const fnPtr = new NativeFunction(shellCode, 'int', []);
    Memory.protect(shellCode, TlsIa32.SHELL_CODE.length, 'r-x');
    const seg = fnPtr();
    Memory.protect(shellCode, TlsIa32.SHELL_CODE.length, 'rw-');
    return new Selector(seg);
  }

  public getTls(): NativePointer {
    const seg = this.getSegment();
    Output.debug(`tls segment: ${seg.toString()}`);

    if (seg.getRpl() !== 3) {
      throw new Error('tls segment is not in user space');
    }

    if (seg.getTi() !== 0) {
      throw new Error('tls segment is in LDT, expected GDT entry');
    }

    const user_desc = new ThreadArea(seg);

    const ret = this.fnSyscall(
      TlsIa32.SYS_get_thread_area,
      user_desc.ptr(),
    ) as UnixSystemFunctionResult<number>;
    if (ret.value !== 0) throw new Error(`syscall failed, errno: ${ret.errno}`);

    Output.debug(`thread area: ${user_desc.toString()}`);

    const tls = user_desc.getBase();
    return tls;
  }

  public static getTls(): NativePointer {
    const tls = new TlsIa32();
    const ptr = tls.getTls();
    return ptr;
  }
}
