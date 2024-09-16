import { Format } from '../misc/format.js';

export class Var {
  private val: string | UInt64;
  private p: NativePointer;
  private readonly literal: string;

  public constructor(val: string | UInt64, literal: string | null = null) {
    this.val = val;
    if (this.val instanceof UInt64) this.p = ptr(val.toString());
    else this.p = Memory.allocUtf8String(val as string);
    this.literal = literal ?? this.val.toString();
  }

  public getLiteral(): string {
    return this.literal;
  }

  public toPointer(): NativePointer {
    return this.p;
  }

  public toU64(): UInt64 {
    if (this.val instanceof UInt64) return this.val as UInt64;
    else return uint64(this.p.toString());
  }

  public compare(other: Var): number {
    return this.toU64().compare(other.toU64());
  }

  public toString(): string {
    if (this.val instanceof UInt64)
      return `${Format.toHexString(this.val)} ${Format.toDecString(this.val)}`;
    else return `${Format.toHexString(this.p)} "${this.val}"`;
  }

  public static ZERO: Var = new Var(uint64(0), 'ZERO');
}
