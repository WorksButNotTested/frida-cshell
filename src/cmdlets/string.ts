import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Mem } from '../memory/mem.js';

const MAX_STRING_LENGTH: number = 1024;
const USAGE: string = `Usage: ds

d address <bytes> - show string
  adress   the address/symbol to read from
`;

export class DumpStringCmdLet extends CmdLet {
  name = 'ds';
  category = 'data';
  help = 'dump string';

  public runSync(tokens: Token[]): Var {
    if (tokens.length !== 1) return this.usage();

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return this.usage();

    const address = v0.toPointer();
    if (address === undefined) return this.usage();

    const name = t0.getLiteral();
    this.dump(name, address);
    return v0;
  }

  private dump(name: string, address: NativePointer) {
    const length = MAX_STRING_LENGTH;
    let bytes: Uint8Array = new Uint8Array(0);
    let lastError: Error | null = null;
    while (length > 0) {
      try {
        bytes = Mem.readBytes(address, length);
        break;
      } catch (error) {
        if (error instanceof Error) {
          lastError = error;
        }
        continue;
      }
    }

    if (length === 0) {
      throw new Error(
        `failed to read string from ${Format.toHexString(address)}, ${lastError}`,
      );
    }

    const cp = Memory.alloc(length + 1);
    cp.writeByteArray(bytes.buffer as ArrayBuffer);

    const value = cp.readUtf8String();
    if (value === null || value.length === 0) {
      Output.writeln(
        `No string found at ${Output.green(name)}: ${Output.yellow(Format.toHexString(address))}`,
      );
    } else {
      Output.write(Output.green(name));
      Output.write(' = ');
      Output.write(Output.blue("'"));
      Output.write(Output.yellow(value));
      Output.write(Output.blue("'"));
      Output.write(', length: ');
      Output.write(Output.blue(value.length.toString()));
      Output.write(' (');
      Output.write(Output.blue(`0x${value.length.toString(16)}`));
      Output.write(')');
      Output.writeln();
    }
  }

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
