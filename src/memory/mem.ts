import { MemoryBps } from '../breakpoints/memory.js';
import { Overlay } from './overlay.js';
import { Format } from '../misc/format.js';

export class Mem {
  public static readBytes(address: NativePointer, length: number): Uint8Array {
    MemoryBps.disable();
    try {
      const data = address.readByteArray(length);
      if (data === null)
        throw new Error(
          `failed to read ${Format.toHexString(length)} bytes from ${Format.toHexString(address)}`,
        );
      const buffer = new Uint8Array(data);
      Overlay.fix(address, buffer);
      return buffer;
    } finally {
      MemoryBps.enable();
    }
  }

  public static writeBytes(address: NativePointer, data: Uint8Array) {
    MemoryBps.disable();
    try {
      if (Overlay.overlaps(address, data.length)) {
        throw new Error(
          `failed to write ${Format.toHexString(data.length)} bytes to ${Format.toHexString(address)} as the address has been modified (check for breakpoints)`,
        );
      }
      this.modifyMemory(address, data);
    } finally {
      MemoryBps.enable();
    }
  }

  private static modifyMemory(address: NativePointer, data: Uint8Array) {
    const alignStart = this.pageAlignDown(address);
    const alignEnd = this.pageAlignUp(address.add(data.length));
    const pageShift = Math.log2(Process.pageSize);
    const numPages = alignEnd.sub(alignStart).shr(pageShift).toInt32();
    const pageAddresses = Array.from({ length: numPages }, (_, i) =>
      alignStart.add(i * Process.pageSize),
    );
    const exitingProtections = pageAddresses.map(a => {
      return { address: a, protection: Memory.queryProtection(a) };
    });
    const hasNonExec = exitingProtections.some(
      pp => pp.protection.charAt(2) !== 'x',
    );

    if (hasNonExec) {
      const newProtections = exitingProtections.map(pp => {
        const newProtection = `${pp.protection.charAt(0)}w${pp.protection.charAt(2)}`;
        return {
          address: pp.address,
          oldProtection: pp.protection,
          newProtection: newProtection,
        };
      });

      newProtections
        .filter(np => np.oldProtection !== np.newProtection)
        .forEach(p => {
          Memory.protect(p.address, Process.pageSize, p.newProtection);
        });

      address.writeByteArray(data.buffer as ArrayBuffer);

      newProtections
        .filter(np => np.oldProtection !== np.newProtection)
        .forEach(p => {
          Memory.protect(p.address, Process.pageSize, p.oldProtection);
        });
    } else {
      Memory.patchCode(address, data.length, ptr =>
        ptr.writeByteArray(data.buffer as ArrayBuffer),
      );
    }
  }

  public static pageAlignDown(addr: NativePointer): NativePointer {
    const pageMask = ptr(Process.pageSize).sub(1).not();
    return addr.and(pageMask);
  }

  public static pageAlignUp(addr: NativePointer): NativePointer {
    return this.pageAlignDown(addr.add(Process.pageSize - 1));
  }
}
