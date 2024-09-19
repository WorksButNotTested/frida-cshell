export class Format {
  public static toHexString(
    ptr: NativePointer | UInt64 | number | null,
  ): string {
    if (ptr === null) return '[UNDEFINED]';
    let hex = ptr.toString(16).padStart(this.is64bit() ? 16 : 8, '0');
    if (this.is64bit()) {
      hex = [hex.slice(0, 8), '`', hex.slice(8)].join('');
    }
    return `0x${hex}`;
  }

  private static is64bit(): boolean {
    switch (Process.arch) {
      case 'x64':
      case 'arm64':
        return true;
      default:
        return false;
    }
  }

  public static toDecString(
    ptr: NativePointer | UInt64 | number | null,
  ): string {
    if (ptr === null) return '[UNDEFINED]';
    return ptr.toString(10).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  public static toSize(ptr: NativePointer | UInt64 | number | null): string {
    if (ptr === null) return '[UNDEFINED]';
    const val = uint64(ptr.toString());
    const gb = uint64(1).shl(30);
    const mb = uint64(1).shl(20);
    const kb = uint64(1).shl(10);

    if (val > gb) {
      return `${val.shr(30).toString().padStart(4, ' ')} GB`;
    } else if (val > mb) {
      return `${val.shr(20).toString().padStart(4, ' ')} MB`;
    } else if (val > kb) {
      return `${val.shr(10).toString().padStart(4, ' ')} KB`;
    } else {
      return `${val.toString().padStart(4, ' ')} B`;
    }
  }

  public static toTextString(bytes: ArrayBuffer): string {
    return String.fromCharCode(...new Uint8Array(bytes));
  }

  public static toByteArray(str: string): ArrayBuffer {
    return new Uint8Array(str.split('').map(c => c.charCodeAt(0)))
      .buffer as ArrayBuffer;
  }
}
