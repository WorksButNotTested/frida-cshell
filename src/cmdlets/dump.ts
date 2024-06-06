import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
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

  public run(tokens: Token[]): Var {
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
    this.dump(address, length);
    return v0;
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
      const prefixed = dump.split('\n').join(`\n${Output.green("0x")}`);
      Output.writeln(prefixed);
    } catch (error) {
      throw new Error(
        `failed to read ${Format.toHexString(length)} bytes from ${Format.toHexString(address)}, ${error}`,
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

    this.dump(address, DEFAULT_LENGTH);
    return v0;
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
