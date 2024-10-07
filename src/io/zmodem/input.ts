import { InputInterceptRaw } from '../input.js';

export class InputBuffer implements InputInterceptRaw {
  public static readonly BLOCK_SIZE: number = 1024;
  private static readonly DELAY: number = 50; // milliseconds

  private bytesPromise: Promise<void>;
  private bytesReceived!: () => void;

  private inputBuffer: ArrayBuffer = new ArrayBuffer(0);
  private debug: (msg: string) => void;

  public constructor(debug: (msg: string) => void) {
    this.debug = debug;
    this.bytesPromise = new Promise<void>(resolve => {
      this.bytesReceived = resolve;
    });
  }

  addRaw(bytes: ArrayBuffer): void {
    if (bytes === null) {
      return;
    }

    const buffer = new Uint8Array(bytes);
    const msg = Array.from(buffer)
      .map(b => `0x${b.toString(16).padStart(2, '0')},`)
      .join(' ');
    this.debug(`- IN: ${msg}`);

    const newBuffer = new Uint8Array(
      this.inputBuffer.byteLength + bytes.byteLength,
    );
    newBuffer.set(new Uint8Array(this.inputBuffer), 0);
    newBuffer.set(new Uint8Array(bytes), this.inputBuffer.byteLength);
    this.inputBuffer = newBuffer.buffer as ArrayBuffer;
    this.bytesReceived();
  }

  abortRaw(): void {}

  public async read(count: number, timeout: number): Promise<ArrayBuffer> {
    const startTime = Date.now();
    do {
      if (this.inputBuffer.byteLength < count) {
        if (timeout === 0) {
          break;
        }

        const timeoutPromise = new Promise<void>(resolve => {
          setTimeout(() => {
            resolve();
          }, InputBuffer.DELAY);
        });

        await Promise.race([this.bytesPromise, timeoutPromise]);

        this.bytesPromise = new Promise<void>(resolve => {
          this.bytesReceived = resolve;
        });
        continue;
      }

      const result = this.inputBuffer.slice(0, count);
      const buffer = new Uint8Array(result);
      const msg = Array.from(buffer)
        .map(b => `0x${b.toString(16).padStart(2, '0')},`)
        .join(' ');
      this.inputBuffer = this.inputBuffer.slice(count);
      this.debug(`- RCV: ${msg} REMAIN: ${this.inputBuffer.byteLength}`);
      return result;
    } while (Date.now() - startTime < timeout);

    throw new Error(
      `timed out waiting for ${count} bytes, only got ${this.inputBuffer.byteLength}`,
    );
  }
}
