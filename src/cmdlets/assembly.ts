import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Mem } from '../memory/mem.js';

const DEFAULT_LENGTH: number = 10;
const USAGE: string = `Usage: l

l address <bytes> - show disassembly listing
  address   the address/symbol to disassemble
  bytes     the number of instructions to disassemble (default ${DEFAULT_LENGTH})
`;

export class AssemblyCmdLet extends CmdLet {
  name = 'l';
  category = 'data';
  help = 'disassembly listing';

  public runSync(tokens: Token[]): Var {
    const retWithLength = this.runWithLength(tokens);
    if (retWithLength !== null) return retWithLength;

    const retWithoutLength = this.runWithoutLength(tokens);
    if (retWithoutLength !== null) return retWithoutLength;

    return this.usage();
  }

  private runWithLength(tokens: Token[]): Var | null {
    if (tokens.length !== 2) return null;

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];
    const [v0, v1] = [t0.toVar(), t1.toVar()];

    if (v0 === null) return null;
    if (v1 === null) return null;

    const address = v0.toPointer();
    const length = v1.toU64().toNumber();

    if (length > 100) throw new Error(`too many instructions: ${length}`);

    return this.list(address, length);
  }

  private list(address: NativePointer, length: number): Var {
    let cursor = address;
    const isThumb = this.isThumb(address);
    if (isThumb) {
      const mask = ptr(1).not();
      cursor = cursor.and(mask);
    }
    let buffer = new Uint8Array(0);

    try {
      const minLength = this.maxInstructionLen();
      const copy = Memory.alloc(Process.pageSize);

      for (let i = 1; i <= length; i++) {
        if (buffer.byteLength < minLength) {
          const newBuff = this.readMaxBytes(
            cursor.add(buffer.byteLength),
            minLength - buffer.byteLength,
          );
          buffer = this.concatBuffers(buffer, newBuff);
        }

        Mem.writeBytes(copy, buffer);
        const insn = Instruction.parse(copy.add(isThumb ? 1 : 0));
        if (insn.size > buffer.length)
          throw new Error(
            `failed to parse instruction at ${cursor}, not enough bytes: ${buffer.length}`,
          );

        const idx = `#${i.toString()}`.padStart(4);
        const insnBytes = buffer.slice(0, insn.size);
        const bytesStr = Array.from(insnBytes)
          .map(n => n.toString(16).padStart(2, '0'))
          .join(' ');

        Output.writeln(
          `${Output.bold(idx)}: ${Output.green(Format.toHexString(cursor))}: ${Output.yellow(insn.toString().padEnd(40))} ${Output.blue(bytesStr)}`,
        );

        cursor = cursor.add(insn.size);
        buffer = buffer.slice(insn.size);
      }

      return new Var(uint64(cursor.toString()));
    } catch (error) {
      throw new Error(
        `failed to parse instruction at ${Format.toHexString(cursor)} (${Format.toHexString(buffer.byteLength)} bytes available), ${error}`,
      );
    }
  }

  private isThumb(address: NativePointer): boolean {
    if (Process.arch !== 'arm') return false;
    if (address.and(1).equals(ptr(0))) return false;
    return true;
  }

  private maxInstructionLen(): number {
    switch (Process.arch) {
      case 'arm':
      case 'arm64':
        return 4;
      case 'ia32':
      case 'x64':
        return 15;
      default:
        throw new Error(`unsupported architecutre: ${Process.arch}`);
    }
  }

  private readMaxBytes(ptr: NativePointer, length: number): Uint8Array {
    for (let i = length; i > 0; i++) {
      try {
        const bytes = Mem.readBytes(ptr, i);
        return bytes;
      } catch {
        continue;
      }
    }
    return new Uint8Array(0);
  }

  private concatBuffers(buffer1: Uint8Array, buffer2: Uint8Array): Uint8Array {
    const concatenatedBuffer = new Uint8Array(buffer1.length + buffer2.length);
    concatenatedBuffer.set(buffer1, 0);
    concatenatedBuffer.set(buffer2, buffer1.byteLength);
    return concatenatedBuffer;
  }

  private runWithoutLength(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const address = v0.toPointer();

    return this.list(address, DEFAULT_LENGTH);
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
