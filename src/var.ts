import { Util } from "./util.js";

export class Var {
  private val: string | UInt64;
  private p: NativePointer;

  public constructor(val: string | UInt64) {
    this.val = val;
    if (this.val instanceof UInt64) this.p = ptr(val.toString());
    else this.p = Memory.allocUtf8String(val as string);
  }

  public toPointer(): NativePointer {
    return this.p;
  }

  public toU64(): UInt64 {
    if (this.val instanceof UInt64) return this.val as UInt64;
    else return uint64(this.p.toString());
  }

  public toString(): string {
    if (this.val instanceof UInt64)
      return `${Util.toHexString(this.val)} ${Util.toDecString(this.val)}`;
    else return `${Util.toHexString(this.p)} "${this.val}"`;
  }

  public static ZERO: Var = new Var(uint64(0));
}
