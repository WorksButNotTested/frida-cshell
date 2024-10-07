import { Output } from '../output.js';

export class OutputBuffer {
  public static readonly BLOCK_SIZE: number = 1024;

  private debug: (msg: string) => void;

  public constructor(debug: (msg: string) => void) {
    this.debug = debug;
  }

  public write(bytes: ArrayBuffer): void {
    const buffer = new Uint8Array(bytes);
    const msg = Array.from(buffer)
      .map(b => `0x${b.toString(16).padStart(2, '0')},`)
      .join(' ');
    this.debug(`- OUT: ${msg}`);
    Output.writeRaw(bytes);
  }
}
