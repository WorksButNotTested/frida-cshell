import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Mem } from '../../memory/mem.js';

export class DumpStringCmdLet extends CmdLetBase {
  name = 'ds';
  category = 'data';
  help = 'dump string';

  private static readonly MAX_STRING_LENGTH: number = 1024;
  private static readonly USAGE: string = `Usage: ds

ds address <bytes> - show string
  adress   the address/symbol to show`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return this.usage();
    const [arg] = vars as [Var];
    this.dump(arg);
    return arg;
  }

  private dump(arg: Var) {
    const name = arg.getLiteral();
    const address = arg.toPointer();
    const length = DumpStringCmdLet.MAX_STRING_LENGTH;
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
      Output.writeln(
        [
          Output.green(name),
          '=',
          `${Output.blue("'")}${Output.yellow(value)}${Output.blue("'")},`,
          `length: ${Output.blue(value.length.toString())},`,
          `(${Output.blue(`0x${value.length.toString(16)}`)})`,
        ].join(' '),
      );
    }
  }

  public usage(): Var {
    Output.writeln(DumpStringCmdLet.USAGE);
    return Var.ZERO;
  }
}
