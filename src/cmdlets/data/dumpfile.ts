import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Mem } from '../../memory/mem.js';

export class DumpFileCmdLet extends CmdLetBase {
  name = 'df';
  category = 'data';
  help = 'dump data to file';

  private static readonly USAGE: string = `Usage: df

df filename address bytes - show data
  filename the name of the file to dump to
  adress   the address/symbol to dump from
  count    the count of fields to dump`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [
      this.parseString,
      this.parseVar,
      this.parseVar,
    ]);
    if (vars === null) return this.usage();
    const [filename, address, length] = vars as [string, Var, Var];
    this.dump(filename, address.toPointer(), length.toU64().toNumber());
    return new Var(filename);
  }

  private dump(filename: string, address: NativePointer, length: number) {
    try {
      const bytes = Mem.readBytes(address, length);
      Output.debug(`writing ${length} bytes from ${address} to ${filename}`);
      File.writeAllBytes(filename, bytes.buffer as ArrayBuffer);
    } catch (error) {
      throw new Error(
        `failed to dump ${Format.toHexString(length)} bytes from ${Format.toHexString(address)} to ${filename}, ${error}`,
      );
    }
  }

  public usage(): Var {
    Output.writeln(DumpFileCmdLet.USAGE);
    return Var.ZERO;
  }
}
