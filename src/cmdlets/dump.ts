import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Mem } from '../memory/mem.js';

const DEFAULT_COUNT: number = 32;

const USAGE: string = `Usage: d

d address <bytes> - show data
  adress   the address/symbol to read from
  count    the count of fields to read (default ${DEFAULT_COUNT})

d address bytes <width> - show data
  adress   the address/symbol to read from
  count    the count of fields to read (default ${DEFAULT_COUNT})
  width    the width of each field in the output (1, 2, 4 or 8)
`;

export class DumpCmdLet extends CmdLet {
  name = 'd';
  category = 'data';
  help = 'dump data from memory';

  public run(tokens: Token[]): Var {
    const retWithLengthAndWidth = this.runWithLengthAndWidth(tokens);
    if (retWithLengthAndWidth !== null) return retWithLengthAndWidth;

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
    const count = v1.toU64().toNumber();
    this.dump(address, count);
    return v0;
  }

  private runWithLengthAndWidth(tokens: Token[]): Var | null {
    if (tokens.length !== 3) return null;

    const [a0, a1, a2] = tokens;
    const [t0, t1, t2] = [a0 as Token, a1 as Token, a2 as Token];

    const [v0, v1] = [t0.toVar(), t1.toVar()];
    const width = this.getWidth(t2);

    if (v0 === null) return null;
    if (v1 === null) return null;
    if (width === null) return null;

    const address = v0.toPointer();
    const count = v1.toU64().toNumber();
    this.dump(address, count, width);
    return v0;
  }

  private getWidth(token: Token): number | null {
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

  private dump(address: NativePointer, count: number, width: number = 1) {
    try {
      const length = count * width;
      const bytes = Mem.readBytes(address, length);

      switch (width) {
        case 1: {
          const dump = hexdump(bytes.buffer as ArrayBuffer, {
            length,
            header: true,
            ansi: true,
            address: address,
          });
          const prefixed = dump.replace(
            new RegExp('\n', 'g'),
            `\n${Output.green('0x')}`,
          );
          Output.writeln(`  ${prefixed}`);
          break;
        }
        default: {
          const output = Memory.alloc(length);
          output.writeByteArray(bytes.buffer as ArrayBuffer);
          Output.write(' '.repeat(2 + Process.pointerSize * 2));
          for (let i = 0; i < 16; i++) {
            if (i % width != 0) continue;
            const hdr = i.toString(16).toUpperCase();
            const padLen = width * 2 + 1 - hdr.length;
            Output.write(` ${hdr.padStart(padLen, ' ')}`);
          }
          for (let i = 0; i < count; i++) {
            const offset = i * width;
            if (offset % 16 == 0) {
              Output.writeln();
              Output.write(
                `${Output.green(Format.toHexString(address.add(offset)))} `,
              );
            }

            const cursor = output.add(offset);
            switch (width) {
              case 2: {
                const val = cursor.readU16();
                const str = val.toString(16).padStart(4, '0');
                Output.write(`${Output.yellow(str)} `);
                break;
              }
              case 4: {
                const val = cursor.readU32();
                const str = val.toString(16).padStart(8, '0');
                Output.write(`${Output.yellow(str)} `);
                break;
              }
              case 8: {
                const val = cursor.readU64();
                const str = val.toString(16).padStart(16, '0');
                Output.write(`${Output.yellow(str)} `);
                break;
              }
            }
          }
          Output.writeln();
        }
      }
    } catch (error) {
      throw new Error(
        `failed to read ${Format.toHexString(count)} bytes from ${Format.toHexString(address)}, ${error}`,
      );
    }
  }

  private runWithoutLength(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const address = v0.toPointer();
    if (address === undefined) return null;

    this.dump(address, DEFAULT_COUNT);
    return v0;
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
