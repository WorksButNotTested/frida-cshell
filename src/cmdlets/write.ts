import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Util } from '../util.js';
import { Token } from '../token.js';
import { Var } from '../var.js';
import { Overlay } from '../overlay.js';

abstract class WriteCmdLet extends CmdLet {
  category = 'data';
  public usage(): Var {
    const usage: string = `Usage: ${this.name}

${this.name} address value - write ${this.SIZE} bytes to memory
    address  the address/symbol to write to
    value    the value to write
        `;
    Output.write(usage);
    return Var.ZERO;
  }
  protected abstract MAX_VALUE: UInt64;
  protected abstract SIZE: number;
  protected abstract write(address: NativePointer, val: UInt64): void;

  public run(tokens: Token[]): Var {
    if (tokens.length != 2) return this.usage();

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return this.usage();

    const address = t0.toPointer();
    if (address === undefined) return this.usage();

    const val = tokens[1]?.toVar()?.toU64();
    if (val === undefined) return this.usage();

    if (Overlay.overlaps(address, this.SIZE))
      throw new Error(
        `Failed to write ${Util.toHexString(this.SIZE)} bytes to ${Util.toHexString(address)} as the address has been modified (check for breakpoints)`,
      );

    Util.modifyMemory(address, this.SIZE, ptr => {
      this.write(ptr, val);
    });

    return t0;
  }
}

export class Write1CmdLet extends WriteCmdLet {
  name = 'w1';
  help = 'write a byte to memory';

  protected MAX_VALUE: UInt64 = uint64(0xff);
  protected SIZE: number = 1;

  protected write(address: NativePointer, val: UInt64) {
    address.writeU8(val.toNumber());
    Output.writeln(
      `Wrote value: 0x${val.toString(16).padStart(2, '0')} = ${val.toString()} to ${Util.toHexString(address)}`,
    );
  }
}

export class Write2CmdLet extends WriteCmdLet {
  name = 'w2';
  help = 'write a half to memory';

  protected MAX_VALUE: UInt64 = uint64(0xffff);
  protected SIZE: number = 2;

  protected write(address: NativePointer, val: UInt64) {
    address.writeU16(val.toNumber());
    Output.writeln(
      `Wrote value: 0x${val.toString(16).padStart(4, '0')} = ${val.toString()} to ${Util.toHexString(address)}`,
    );
  }
}

export class Write4CmdLet extends WriteCmdLet {
  name = 'w4';
  help = 'write a word to memory';

  protected MAX_VALUE: UInt64 = uint64(0xffffffff);
  protected SIZE: number = 4;

  protected write(address: NativePointer, val: UInt64) {
    address.writeU32(val.toNumber());
    Output.writeln(
      `Wrote value: 0x${val.toString(16).padStart(8, '0')} = ${val.toString()} to ${Util.toHexString(address)}`,
    );
  }
}

export class Write8CmdLet extends WriteCmdLet {
  name = 'w8';
  help = 'write a double word to memory';

  protected MAX_VALUE: UInt64 = uint64('0xffffffffffffffff');
  protected SIZE: number = 8;

  protected write(address: NativePointer, val: UInt64) {
    address.writeU64(val);
    Output.writeln(
      `Wrote value: ${Util.toHexString(val)} = ${val.toString()} to ${Util.toHexString(address)}`,
    );
  }
}
