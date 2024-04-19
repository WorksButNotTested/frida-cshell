import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Util } from '../misc/util.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Mem } from '../memory/mem.js';

const DEFAULT_LENGTH: number = 32;

const USAGE: string = `Usage: d

d address <bytes> - show data
  adress   the address/symbol to read from
  bytes    the numer of bytes to read (default ${DEFAULT_LENGTH})
`;

export class DumpCmdLet extends CmdLet {
  name = 'd';
  category = 'data';
  help = 'dump data from memory';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private dump(address: NativePointer, length: number) {
    try {
      const bytes = Mem.readBytes(address, length);

      const dump = hexdump(bytes.buffer as ArrayBuffer, {
        length: length,
        header: true,
        ansi: true,
        address: address,
      });
      Output.writeln(dump);
    } catch (error) {
      throw new Error(
        `Failed to read ${Util.toHexString(length)} bytes from ${Util.toHexString(address)}, ${error}`,
      );
    }
  }

  private runWithLength(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return undefined;

    const address = t0.toPointer();
    if (address === undefined) return undefined;

    const length = tokens[1]?.toVar()?.toU64().toNumber();
    if (length === undefined) return undefined;

    this.dump(address, length);
    return t0;
  }

  private runWithoutLength(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return undefined;

    const address = t0.toPointer();
    if (address === undefined) return undefined;

    this.dump(address, DEFAULT_LENGTH);
    return t0;
  }

  public run(tokens: Token[]): Var {
    const retWithLength = this.runWithLength(tokens);
    if (retWithLength !== undefined) return retWithLength;

    const retWithoutLength = this.runWithoutLength(tokens);
    if (retWithoutLength !== undefined) return retWithoutLength;

    return this.usage();
  }
}
