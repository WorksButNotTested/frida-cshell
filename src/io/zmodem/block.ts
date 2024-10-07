import { Chars, Escape, Zdle } from './constants.js';
import { Crc16 } from './crc.js';

export class Block {
  public static readonly MAX_BLOCK_SIZE: number = 1024;

  private static lastSent = 0;

  private bytes: number[] = [];

  private checkByte(b: number) {
    if (b < 0 || b > 0xff) throw new Error(`byte: ${b} out of range`);
  }

  private shouldEscape(b: number): Escape {
    this.checkByte(b);
    if ((b & 0x60) != 0) {
      return Escape.ESCAPE_NEVER;
    }

    /*
     * ZMODEM software escapes ZDLE, 020, 0220, 021, 0221, 023, and 0223.
     * If preceded by 0100 or 0300 (@), 015 and 0215 are also escaped to protect the Telenet command escape CR-@-CR.
     * The receiver ignores 021, 0221, 023, and 0223 characters in the data stream.
     */

    /*
     * ZMODEM software escapes 24 (CAN - ZDLE), 16 (DLE), 17 (DC1 - XON), 19 (DC3 - XOFF) (and 144, 145, 147)
     * If preceded by 64 (or 192) (@), 13 (CR) (and 141) are also escaped to protect the Telenet command escape CR-@-CR.
     * The receiver ignores 021, 0221, 023, and 0223 characters in the data stream.
     */
    switch (b) {
      case Chars.ZDLE:
      case Chars.DLE:
      case Chars.DLE | 0x80:
      case Chars.XON:
      case Chars.XON | 0x80:
      case Chars.XOFF:
      case Chars.XOFF | 0x80:
        return Escape.ESCAPE_ALWAYS;
      case Chars.CR:
      case Chars.CR | 0x80:
        return Escape.ESCAPE_AFTER_AT;
      default:
        return Escape.ESCAPE_NEVER;
    }
  }

  private writeByte(b: number) {
    this.checkByte(b);
    const esc = this.shouldEscape(b);
    if (
      esc === Escape.ESCAPE_ALWAYS ||
      (esc === Escape.ESCAPE_AFTER_AT && Block.lastSent === Chars.AT)
    ) {
      this.bytes.push(Chars.ZDLE);
      this.bytes.push(b ^ 0x40);
      Block.lastSent = b ^ 0x40;
    } else {
      this.bytes.push(b);
      Block.lastSent = b;
    }
  }

  public constructor(data: ArrayBuffer | null, frameEnd: Zdle) {
    const crc = new Crc16();
    if (data !== null) {
      const buffer = new Uint8Array(data);
      buffer.forEach(b => {
        this.writeByte(b);
        crc.update(b);
      });
    }

    this.bytes.push(Chars.ZDLE);
    this.bytes.push(frameEnd);
    crc.update(frameEnd);

    crc.update(0);
    crc.update(0);

    this.writeByte(crc.value >> 8);
    this.writeByte(crc.value & 0xff);

    if (frameEnd === Zdle.ZCRCW) {
      this.writeByte(Chars.XON);
    }
  }

  public get data(): ArrayBuffer {
    return new Uint8Array(this.bytes).buffer as ArrayBuffer;
  }
}
