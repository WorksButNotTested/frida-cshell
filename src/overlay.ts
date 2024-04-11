import { Base64 } from './base64.js';
import { Util } from './util.js';

export class Overlay {
  private readonly address: NativePointer;
  private readonly length: number;
  private readonly data: Uint8Array;
  private refCount = 0;

  public constructor(address: NativePointer, length: number) {
    const bytes = address.readByteArray(length);
    if (bytes === null)
      throw new Error(
        `Failed to read: ${Util.toHexString(address)}, length: ${length}`,
      );
    this.address = address;
    this.length = length;
    this.data = new Uint8Array(bytes);
  }

  public toString(): string {
    return `address: ${this.address}, length: ${this.length}, data: ${this.data}, refCount: ${this.refCount}`;
  }

  public static overlays: [string, Overlay][] = [];
  private static readonly KEY_LENGTH: number = 32;

  private static generateKey(): string {
    const numbers = Array.from({ length: this.KEY_LENGTH }, () =>
      Math.floor(Math.random() * 256),
    );
    const bytes = new Uint8Array(numbers);
    const key = Base64.encode(bytes);
    return key;
  }

  public static add(address: NativePointer, length: number): string {
    const key = this.generateKey();
    this.overlays.unshift([key, new Overlay(address, length)]);
    return key;
  }

  public static remove(key: string) {
    const index = this.overlays.findIndex(([k, _v]) => k === key);
    if (index === -1) throw new Error(`Failed to find overlay key: ${key}`);
    this.overlays.splice(index, 1);
  }
}
