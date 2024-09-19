import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Mem } from '../../memory/mem.js';

const USAGE: string = `Usage: cp

cp dest src bytes - copy data
  dest   the address/symbol to write to
  src    the address/symbol to read from
  bytes    the numer of bytes to read`;

export class CopyCmdLet extends CmdLet {
  name = 'cp';
  category = 'data';
  help = 'copy data in memory';

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [
      this.parseVar,
      this.parseVar,
      this.parseVar,
    ]);
    if (vars === null) return this.usage();
    const [v0, v1, v2] = vars as [Var, Var, Var];

    const dst = v0.toPointer();
    const src = v1.toPointer();
    const len = v2.toU64().toNumber();

    try {
      const buff = Mem.readBytes(src, len);
      Mem.writeBytes(dst, buff);
    } catch (error) {
      throw new Error(
        `failed to copy ${len} bytes from ${Format.toHexString(src)} to ${Format.toHexString(dst)}, ${error}`,
      );
    }
    return v0;
  }

  public usage(): Var {
    Output.writeln(USAGE);
    return Var.ZERO;
  }
}
