import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Util } from '../util.js';
import { Token } from '../token.js';
import { Var } from '../var.js';

const USAGE: string = `Usage: cp

d dest src bytes - copy data
  dest   the address/symbol to write to
  src    the address/symbol to read from  
  bytes    the numer of bytes to read
`;

export class CopyCmdLet extends CmdLet {
  name = 'cp';
  category = 'data';
  help = 'copy data in memory';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    if (tokens.length != 3) return this.usage();

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return this.usage();

    const dst = t0.toPointer();
    if (dst === undefined) return this.usage();

    const src = tokens[1]?.toVar()?.toPointer();
    if (src === undefined) return this.usage();

    const len = tokens[2]?.toVar()?.toU64().toNumber();
    if (len === undefined) return this.usage();

    try {
      Memory.copy(dst, src, len);
    } catch (error) {
      throw new Error(
        `Failed to copy ${len} bytes from ${Util.toHexString(src)} to ${Util.toHexString(dst)}, ${error}`,
      );
    }
    return t0;
  }
}
