import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Util } from '../util.js';
import { Token } from '../token.js';
import { Var } from '../var.js';
import { Overlay } from '../overlay.js';

const DEFAULT_LENGTH: number = 32;
const USAGE: string = `Usage: l

l address <bytes> - show disassembly listing
  address   the address/symbol to disassemble
  bytes     the number of bytes to disassemble (default ${DEFAULT_LENGTH})
`;

export class AssemblyCmdLet extends CmdLet {
  name = 'l';
  category = 'data';
  help = 'disassembly listing';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private list(address: NativePointer, length: number): Var {
    try {
      const copy = Memory.alloc(length);

      const buff = address.readByteArray(length);
      if (buff === null) {
        throw new Error(
          `Failed to read ${Util.toHexString(length)} bytes from ${Util.toHexString(address)}`,
        );
      }

      const bytes = new Uint8Array(buff);
      Overlay.fix(address, bytes);

      copy.writeByteArray(bytes.buffer as ArrayBuffer);
      let read = 0;
      let insn = Instruction.parse(copy);
      while (read < length) {
        read += insn.size;
        Output.writeln(
          `${Util.toHexString(address.add(read))}: ${insn.toString()}`,
        );
        insn = Instruction.parse(insn.next);
      }
      return new Var(uint64(insn.next.toString()));
    } catch (error) {
      throw new Error(
        `Failed to read ${Util.toHexString(length)} bytes from ${Util.toHexString(address)}, ${error}`,
      );
    }
  }

  private runWithLength(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const address = tokens[0]?.toVar()?.toPointer();
    if (address === undefined) return undefined;

    const length = tokens[1]?.toVar()?.toU64().toNumber();
    if (length === undefined) return undefined;
    return this.list(address, length);
  }

  private runWithoutLength(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const address = tokens[0]?.toVar()?.toPointer();
    if (address === undefined) return undefined;

    return this.list(address, DEFAULT_LENGTH);
  }

  public run(tokens: Token[]): Var {
    const retWithLength = this.runWithLength(tokens);
    if (retWithLength !== undefined) return retWithLength;

    const retWithoutLength = this.runWithoutLength(tokens);
    if (retWithoutLength !== undefined) return retWithoutLength;

    return this.usage();
  }
}
