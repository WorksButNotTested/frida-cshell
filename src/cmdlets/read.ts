import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Util } from '../util.js';
import { Token } from '../token.js';
import { Var } from '../var.js';

abstract class ReadCmdLet extends CmdLet {
  category = 'data';

  public usage(): Var {
    const usage: string = `Usage: ${this.name}

${this.name} address - read ${this.SIZE} bytes from memory
  address   the address/symbol to read from`;

    Output.write(usage);
    return Var.ZERO;
  }

  protected abstract SIZE: number;
  protected abstract read(address: NativePointer): UInt64;

  public run(tokens: Token[]): Var {
    if (tokens.length != 1) return this.usage();

    const address = tokens[0]?.toVar()?.toPointer();
    if (address === undefined) return this.usage();

    return new Var(this.read(address));
  }
}

export class Read1CmdLet extends ReadCmdLet {
  name = 'r1';
  help = 'read a byte from memory';

  protected SIZE: number = 1;

  protected read(address: NativePointer): UInt64 {
    const val = address.readU8();
    Output.writeln(
      `Read value: 0x${val.toString(16).padStart(2, '0')} = ${val.toString()} `,
    );
    return uint64(val);
  }
}

export class Read2CmdLet extends ReadCmdLet {
  name = 'r2';
  help = 'read a half from memory';

  protected SIZE: number = 2;

  protected read(address: NativePointer): UInt64 {
    const val = address.readU16();
    Output.writeln(
      `Read value: 0x${val.toString(16).padStart(4, '0')} = ${val.toString()} `,
    );
    return uint64(val);
  }
}

export class Read4CmdLet extends ReadCmdLet {
  name = 'r4';
  help = 'read a word from memory';

  protected SIZE: number = 4;

  protected read(address: NativePointer): UInt64 {
    const val = address.readU32();
    Output.writeln(
      `Read value: 0x${val.toString(16).padStart(8, '0')} = ${val.toString()} `,
    );
    return uint64(val);
  }
}

export class Read8CmdLet extends ReadCmdLet {
  name = 'r8';
  help = 'read a double word from memory';

  protected SIZE: number = 8;

  protected read(address: NativePointer): UInt64 {
    const val = address.readU64();
    Output.writeln(`Read value: ${Util.toHexString(val)} = ${val.toString()} `);
    return val;
  }
}
