import { Base64 } from '../misc/base64.js';
import { Mem } from './mem.js';

export class Overlay {
  private readonly address: NativePointer;
  private readonly data: Uint8Array;

  public constructor(address: NativePointer, length: number) {
    const data = Mem.readBytes(address, length);
    this.address = address;
    this.data = data;
  }

  private overlaps(addr: NativePointer, length: number): boolean {
    if (this.address.add(this.data.length).compare(addr) <= 0) return false;
    if (this.address.compare(addr.add(length)) >= 0) return false;
    return true;
  }

  public fix(addr: NativePointer, data: Uint8Array): void {
    if (!this.overlaps(addr, data.length)) return;

    const thisEnd = this.address.add(this.data.length);
    const otherEnd = addr.add(data.length);

    const overlapStart = Overlay.maxPtr(addr, this.address);
    const overlapEnd = Overlay.minPtr(otherEnd, thisEnd);

    const thisOverlapOffset = overlapStart.sub(this.address).toUInt32();
    const otherOverlapOffset = overlapStart.sub(addr).toUInt32();

    const overlapLength = overlapEnd.sub(overlapStart).toUInt32();
    const thisOverlapData = this.data.subarray(
      thisOverlapOffset,
      thisOverlapOffset + overlapLength,
    );

    data.set(thisOverlapData, otherOverlapOffset);
  }

  public static maxPtr(a: NativePointer, b: NativePointer): NativePointer {
    if (a.compare(b) > 0) return a;
    else return b;
  }

  public static minPtr(a: NativePointer, b: NativePointer): NativePointer {
    if (a.compare(b) < 0) return a;
    else return b;
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
    if (index === -1) throw new Error(`failed to find overlay key: ${key}`);
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
