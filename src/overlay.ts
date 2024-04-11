import { Base64 } from './base64.js';
import { Util } from './util.js';

export class Overlay {
  private readonly address: NativePointer;
  private readonly data: Uint8Array;

  public constructor(address: NativePointer, length: number) {
    const bytes = address.readByteArray(length);
    if (bytes === null)
      throw new Error(
        `Failed to read: ${Util.toHexString(address)}, length: ${length}`,
      );
    this.address = address;
    this.data = new Uint8Array(bytes);
  }

  private overlaps(addr: NativePointer, length: number): boolean {
    if (this.address.add(this.data.length).compare(addr) < 0) return false;
    if (this.address.compare(addr.add(length)) > 0) return false;
    return true;
  }

  public fix(addr: NativePointer, data: Uint8Array): void {
    if (!this.overlaps(addr, data.length)) return;

    const thisEnd = this.address.add(this.data.length);
    const otherEnd = addr.add(data.length);

    const overlapStart = Util.maxPtr(addr, this.address);
    const overlapEnd = Util.minPtr(otherEnd, thisEnd);

    const thisOverlapOffset = overlapStart.sub(this.address).toUInt32();
    const otherOverlapOffset = overlapStart.sub(addr).toUInt32();

    const overlapLength = overlapEnd.sub(overlapStart).toUInt32();
    const thisOverlapData = this.data.subarray(
      thisOverlapOffset,
      thisOverlapOffset + overlapLength,
    );

    data.set(thisOverlapData, otherOverlapOffset);
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

  public static fix(address: NativePointer, data: Uint8Array) {
    for (const [_, o] of this.overlays) {
      o.fix(address, data);
    }
  }

  public static overlaps(address: NativePointer, length: number) {
    return this.overlays.some(([_, v]) => v.overlaps(address, length));
  }
}
