import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Mem } from '../../memory/mem.js';

export class DumpCmdLet extends CmdLet {
  name = 'd';
  category = 'data';
  help = 'dump data from memory';

  private static readonly ROW_WIDTH: number = 16;
  private static readonly DEFAULT_COUNT: number = 32;

  private static readonly USAGE: string = `Usage: d

d address <bytes> - show data
  adress   the address/symbol to read from
  count    the count of fields to read (default ${DumpCmdLet.DEFAULT_COUNT})

d address bytes <width> - show data
  adress   the address/symbol to read from
  count    the count of fields to read (default ${DumpCmdLet.DEFAULT_COUNT})
  width    the width of each field in the output (1, 2, 4 or 8)`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar],
      [this.parseVar, this.parseWidth],
    );
    if (vars === null) return this.usage();
    const [[v0], [v1, v2]] = vars as [[Var], [Var | null, number | null]];

    const address = v0.toPointer();
    const count =
      v1 === null ? DumpCmdLet.DEFAULT_COUNT : v1.toU64().toNumber();
    const width = v2 === null ? 1 : v2;
    this.dump(address, count, width);
    return v0;
  }

  private dump(address: NativePointer, count: number, width: number = 1) {
    try {
      const length = count * width;
      const bytes = Mem.readBytes(address, length);

      const output = Memory.alloc(length);
      output.writeByteArray(bytes.buffer as ArrayBuffer);
      const headerPrefix = ' '.repeat(1 + Process.pointerSize * 2);
      const headers = [...Array(DumpCmdLet.ROW_WIDTH).keys()]
        .map(i => {
          if (i % width !== 0) return '';
          const hdr = i.toString(16).toUpperCase();
          const padLen = width * 2 + 1 - hdr.length;
          return ` ${hdr.padStart(padLen, ' ')}`;
        })
        .join('');
      const byteHeaders = width === 1 ? '0123456789ABCDEF' : '';
      Output.writeln([headerPrefix, headers, byteHeaders].join(' '), true);

      const startAddress = address.and(~(DumpCmdLet.ROW_WIDTH - 1));
      const endAddress = address
        .add(length)
        .add(DumpCmdLet.ROW_WIDTH - 1)
        .and(~(DumpCmdLet.ROW_WIDTH - 1));
      const numChunks =
        endAddress.sub(startAddress).toUInt32() / DumpCmdLet.ROW_WIDTH;

      const rows = [...Array(numChunks).keys()]
        .map(i => {
          return startAddress.add(i * DumpCmdLet.ROW_WIDTH);
        })
        .map(rowAddress => {
          const headerPrefix = `${Output.green(Format.toHexString(rowAddress))}`;
          const values = [...Array(DumpCmdLet.ROW_WIDTH / width).keys()].map(
            i => {
              const offset = i * width;
              const rowCursor = rowAddress.add(offset);
              const limit = address.add(length);
              if (rowCursor < address) return ''.padStart(width * 2, ' ');
              if (rowCursor >= limit) return ''.padStart(width * 2, ' ');
              switch (width) {
                case 1: {
                  const val = rowCursor.readU8();
                  const str = val.toString(16).padStart(2, '0');
                  return `${Output.yellow(str)}`;
                }
                case 2: {
                  const val = rowCursor.readU16();
                  const str = val.toString(16).padStart(4, '0');
                  return `${Output.yellow(str)}`;
                }
                case 4: {
                  const val = rowCursor.readU32();
                  const str = val.toString(16).padStart(8, '0');
                  return `${Output.yellow(str)}`;
                }
                case 8: {
                  const val = rowCursor.readU64();
                  const str = val.toString(16).padStart(16, '0');
                  return `${Output.yellow(str)}`;
                }
                default: {
                  throw new Error(`invalid width: ${width}`);
                }
              }
            },
          );
          if (width === 1) {
            const hexDigits = [...Array(DumpCmdLet.ROW_WIDTH).keys()]
              .map(i => {
                const rowCursor = rowAddress.add(i);
                const limit = address.add(length);
                if (rowCursor < address) return ' ';
                if (rowCursor >= limit) return ' ';
                const val = rowCursor.readU8();
                if (val >= 32 && val <= 126) {
                  return String.fromCharCode(val);
                } else {
                  return '.';
                }
              })
              .join('');
            return `${headerPrefix} ${values.join(' ')} ${Output.yellow(hexDigits)}`;
          } else {
            return `${headerPrefix} ${values.join(' ')}`;
          }
        });
      rows.forEach(l => {
        Output.writeln(l, true);
      });
    } catch (error) {
      throw new Error(
        `failed to read ${Format.toHexString(count)} bytes from ${Format.toHexString(address)}, ${error}`,
      );
    }
  }

  public usage(): Var {
    Output.writeln(DumpCmdLet.USAGE);
    return Var.ZERO;
  }
}
