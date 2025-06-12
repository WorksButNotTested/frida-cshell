export enum Endianness {
  Big = 'big',
  Little = 'little',
}

export class Endian {
  private static endianness: Endianness | null = null;
  private static readonly TEST_VALUE_SIZE: number = 4;
  private static readonly TEST_VALUE: number = 0x12345678;

  private static readonly LITTLE_ENDIAN_TEST: Uint8Array = new Uint8Array([
    0x78, 0x56, 0x34, 0x12,
  ]);

  private static readonly BIG_ENDIAN_TEST: Uint8Array = new Uint8Array([
    0x12, 0x34, 0x56, 0x78,
  ]);

  public static get(): Endianness | null {
    if (Endian.endianness !== null) {
      return Endian.endianness;
    }
    const mem = Memory.alloc(Endian.TEST_VALUE_SIZE);
    mem.writeU32(Endian.TEST_VALUE);
    const buffer = mem.readByteArray(Endian.TEST_VALUE_SIZE);
    if (buffer === null) {
      return null;
    }
    const bytes = new Uint8Array(buffer);
    const matches = (a: Uint8Array, b: Uint8Array) =>
      a.every((v, i) => v === b[i]);

    if (matches(Endian.LITTLE_ENDIAN_TEST, bytes)) {
      return (Endian.endianness = Endianness.Little);
    } else if (matches(Endian.BIG_ENDIAN_TEST, bytes)) {
      return (Endian.endianness = Endianness.Big);
    }
    return null;
  }
}
