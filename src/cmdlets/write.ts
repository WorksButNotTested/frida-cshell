import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Mem } from '../memory/mem.js';

export class WriteCmdLet extends CmdLet {
  name = 'w';
  category = 'data';
  help = 'write data to memory';

  public usage(): Var {
    const usage: string = `Usage: w

w n address value - write 'n' bytes to memory
    n        the number of bytes to read (1, 2, 4 or 8).
    address  the address/symbol to write to
    value    the value to write
        `;
    Output.write(usage);
    return Var.ZERO;
  }

  private getLength(token: Token): number | null {
    const literal = token.getLiteral();
    switch (literal) {
      case '1':
        return 1;
      case '2':
        return 2;
      case '4':
        return 4;
      case '8':
        return 8;
      default:
        return null;
    }
  }

  private getMax(length: number): UInt64 {
    switch (length) {
      case 1:
        return uint64(0xff);
      case 2:
        return uint64(0xffff);
      case 4:
        return uint64(0xffffffff);
      case 8:
        return uint64('0xffffffffffffffff');
      default:
        throw new Error(`unsupported length: ${length}`);
    }
  }

  private write(address: NativePointer, val: UInt64, length: number) {
    switch (length) {
      case 1:
        address.writeU8(val.toNumber());
        Output.writeln(
          `Wrote value: 0x${val.toString(16).padStart(2, '0')} = ${val.toString()} to ${Format.toHexString(address)}`,
        );
        break;

      case 2:
        address.writeU16(val.toNumber());
        Output.writeln(
          `Wrote value: 0x${val.toString(16).padStart(4, '0')} = ${val.toString()} to ${Format.toHexString(address)}`,
        );
        break;

      case 4:
        address.writeU32(val.toNumber());
        Output.writeln(
          `Wrote value: 0x${val.toString(16).padStart(8, '0')} = ${val.toString()} to ${Format.toHexString(address)}`,
        );
        break;
      case 8:
        address.writeU64(val);
        Output.writeln(
          `Wrote value: ${Format.toHexString(val)} = ${val.toString()} to ${Format.toHexString(address)}`,
        );
        break;
      default:
        throw new Error(`unsupported length: ${length}`);
    }
  }

  public run(tokens: Token[]): Var {
    if (tokens.length !== 3) return this.usage();

    const [a0, a1, a2] = tokens;
    const [t0, t1, t2] = [a0 as Token, a1 as Token, a2 as Token];
    const [v1, v2] = [t1.toVar(), t2.toVar()];

    if (v1 === null) return this.usage();
    if (v2 === null) return this.usage();

    const length = this.getLength(t0);
    if (length === null) return this.usage();

    const address = v1.toPointer();
    const val = v2.toU64();

    const max = this.getMax(length);
    if (val.compare(max) > 0) {
      throw new Error(
        `value: ${Format.toHexString(val)} larger than maximum ${Format.toHexString(max)}`,
      );
    }

    const copy = Memory.alloc(Process.pageSize);
    this.write(copy, val, length);
    const buff = Mem.readBytes(copy, length);
    Mem.writeBytes(address, buff);

    return v1;
  }
}
