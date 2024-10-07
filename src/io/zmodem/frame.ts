import { Chars, FrameType, Header } from './constants.js';
import { Crc16 } from './crc.js';

export class Frame {
  public static readonly FRAME_SIZE: number = 21;
  public static readonly ZFIN_FRAME_SIZE: number = 20;

  private static readonly HEX_CHARS: Uint8Array = new Uint8Array(
    '0123456789abcdef'.split('').map(c => c.charCodeAt(0)),
  );

  private static fromHexBytes(hi: number, lo: number) {
    const hiChar = Frame.HEX_CHARS.indexOf(hi) as number;
    const loChar = Frame.HEX_CHARS.indexOf(lo) as number;
    if (hiChar < 0) throw new Error(`invalid hex char: ${hi}`);
    if (loChar < 0) throw new Error(`invalid hex char: ${hi}`);
    return (hiChar << 4) + loChar;
  }

  private checkByte(b: number) {
    if (b < 0 || b > 0xff) throw new Error(`byte: ${b} out of range`);
  }

  private toHexBytes(b: number): { hi: number; lo: number } {
    this.checkByte(b);
    const hi = (b >> 4) & 0xf;
    const lo = b & 0xf;
    const hiChar = Frame.HEX_CHARS[hi] as number;
    const loChar = Frame.HEX_CHARS[lo] as number;
    return { hi: hiChar, lo: loChar };
  }

  public static fromBytes(bytes: ArrayBuffer): Frame {
    if (bytes.byteLength < Frame.ZFIN_FRAME_SIZE) {
      throw new Error(`invalid frame size: ${bytes.byteLength}`);
    }

    const array = new Uint8Array(bytes);
    const buffer = Array.from(array);

    if (buffer.shift() !== Chars.ZPAD) {
      throw new Error('expected ZPAD');
    }

    if (buffer.shift() !== Chars.ZPAD) {
      throw new Error('expected ZPAD');
    }

    if (buffer.shift() !== Chars.ZDLE) {
      throw new Error('expected ZDLE');
    }

    if (buffer.shift() !== Header.ZHEX) {
      throw new Error('expected ZHEX');
    }

    const frame = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );
    const p0 = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );
    const p1 = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );
    const p2 = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );
    const p3 = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );

    const crcHi = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );
    const crcLo = Frame.fromHexBytes(
      buffer.shift() as number,
      buffer.shift() as number,
    );
    const crc = (crcHi << 8) | crcLo;

    if (buffer.shift() !== Chars.CR) {
      throw new Error('expected CR');
    }

    if (buffer.shift() !== (Chars.LF | 0x80)) {
      throw new Error('expected LF');
    }

    switch (frame) {
      case FrameType.ZFIN:
      case FrameType.ZACK:
        break;
      default:
        if (buffer.shift() !== Chars.XON) {
          throw new Error('expected XON');
        }
        break;
    }

    const calcCrc = new Crc16();
    const fields = [frame, p0, p1, p2, p3, 0, 0];
    fields.forEach(field => calcCrc.update(field));

    if (crc != calcCrc.value) {
      throw new Error(
        [
          `mismatched crc: 0x${crc.toString(16).padStart(4, '0')}`,
          `calculated: 0x${calcCrc.value.toString(16).padStart(4, '0')}`,
        ].join(', '),
      );
    }

    return new Frame(frame, p0, p1, p2, p3);
  }

  public get data(): ArrayBuffer {
    const bytes: number[] = [];
    bytes.push(Chars.ZPAD);
    bytes.push(Chars.ZPAD);
    bytes.push(Chars.ZDLE);
    bytes.push(Header.ZHEX);

    const typeChars = this.toHexBytes(this.type);
    bytes.push(typeChars.hi);
    bytes.push(typeChars.lo);

    const p0Chars = this.toHexBytes(this.p0);
    bytes.push(p0Chars.hi);
    bytes.push(p0Chars.lo);

    const p1Chars = this.toHexBytes(this.p1);
    bytes.push(p1Chars.hi);
    bytes.push(p1Chars.lo);

    const p2Chars = this.toHexBytes(this.p2);
    bytes.push(p2Chars.hi);
    bytes.push(p2Chars.lo);

    const p3Chars = this.toHexBytes(this.p3);
    bytes.push(p3Chars.hi);
    bytes.push(p3Chars.lo);

    const crc = new Crc16();
    const fields = [this.type, this.p0, this.p1, this.p2, this.p3, 0, 0];
    fields.forEach(field => crc.update(field));

    const crcHi = this.toHexBytes(crc.value >> 8);
    bytes.push(crcHi.hi);
    bytes.push(crcHi.lo);

    const crcLo = this.toHexBytes(crc.value & 0xff);
    bytes.push(crcLo.hi);
    bytes.push(crcLo.lo);

    bytes.push(Chars.CR);
    bytes.push(Chars.LF | 0x80);

    switch (this.type) {
      case FrameType.ZFIN:
      case FrameType.ZACK:
        break;
      default:
        bytes.push(Chars.XON);
        break;
    }

    const bytesArray = new Uint8Array(bytes);
    return bytesArray.buffer as ArrayBuffer;
  }

  public type: number;
  public p0: number;
  public p1: number;
  public p2: number;
  public p3: number;

  public constructor(
    type: number,
    p0: number,
    p1: number,
    p2: number,
    p3: number,
  ) {
    this.type = type;
    this.p0 = p0;
    this.p1 = p1;
    this.p2 = p2;
    this.p3 = p3;
  }

  public toString(): string {
    return `type: ${this.type}, p0: ${this.p0}, p1: ${this.p1}, p2: ${this.p2}, p3: ${this.p3}`;
  }
}
