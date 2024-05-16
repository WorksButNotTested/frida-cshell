import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Util } from '../misc/util.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Mem } from '../memory/mem.js';

export class ReadCmdLet extends CmdLet {
  name = 'r';
  category = 'data';
  help = 'read data from memory';

  public usage(): Var {
    const usage: string = `Usage: r

r n address - read 'n' bytes from memory
  n         the number of bytes to read (1, 2, 4 or 8).
  address   the address/symbol to read from`;

    Output.write(usage);
    return Var.ZERO;
  }

  private getLength(token: Token | undefined): number | undefined {
    if (token === undefined) return undefined;
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
        return undefined;
    }
  }

  private read(address: NativePointer, length: number): UInt64 {
    switch (length) {
      case 1: {
        const val = address.readU8();
        Output.writeln(
          `Read value: 0x${val.toString(16).padStart(2, '0')} = ${val.toString()} `,
        );
        return uint64(val);
      }
      case 2: {
        const val = address.readU16();
        Output.writeln(
          `Read value: 0x${val.toString(16).padStart(4, '0')} = ${val.toString()} `,
        );
        return uint64(val);
      }
      case 4: {
        const val = address.readU32();
        Output.writeln(
          `Read value: 0x${val.toString(16).padStart(8, '0')} = ${val.toString()} `,
        );
        return uint64(val);
      }
      case 8: {
        const val = address.readU64();
        Output.writeln(
          `Read value: ${Util.toHexString(val)} = ${val.toString()} `,
        );
        return val;
      }
      default:
        throw new Error(`unsupported length: ${length}`);
    }
  }

  public run(tokens: Token[]): Var {
    if (tokens.length !== 2) return this.usage();

    const length = this.getLength(tokens[0]);
    if (length === undefined) return this.usage();

    const address = tokens[1]?.toVar()?.toPointer();
    if (address === undefined) return this.usage();

    const buff = Mem.readBytes(address, length);
    const copy = Memory.alloc(Process.pageSize);
    Mem.writeBytes(copy, buff);

    return new Var(this.read(copy, length));
  }
}
