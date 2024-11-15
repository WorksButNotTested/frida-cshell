import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class ErrnoCmdLet extends CmdLetBase {
  name = 'errno';
  category = 'misc';
  help = 'displays the errno value';
  private static readonly USAGE: string = `Usage: errno

errno - display the errno value`;

  private fnErrnoLocation: SystemFunction<NativePointer, []> | null = null;

  public runSync(tokens: Token[]): Var {
    const retGetErrno = this.getErrno(tokens);
    if (retGetErrno !== null) return retGetErrno;

    const retSetErrno = this.setErrno(tokens);
    if (retSetErrno !== null) return retSetErrno;

    return this.usage();
  }

  private setErrno(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return null;
    const [value] = vars as [Var];

    const errno = value.toU64().toNumber();
    const location = this.getErrnoLocation();
    location.writeInt(errno);
    return value;
  }

  private getErrno(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;
    const location = this.getErrnoLocation();

    const errno = location.readInt();
    Output.writeln(`errno: ${errno}`);

    return new Var(uint64(errno), 'errno');
  }

  private getErrnoLocation(): NativePointer {
    const fnErrnoLocation = this.fnErrnoLocation as SystemFunction<
      NativePointer,
      []
    >;
    const location =
      fnErrnoLocation() as UnixSystemFunctionResult<NativePointer>;
    if (location.value.equals(ptr(0)))
      throw new Error('failed to get __errno_location()');
    return location.value;
  }

  public usage(): Var {
    Output.writeln(ErrnoCmdLet.USAGE);
    return Var.ZERO;
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'linux': {
        const pErrnoLocation = Module.findExportByName(
          null,
          '__errno_location',
        );
        if (pErrnoLocation === null) return false;
        this.fnErrnoLocation = new SystemFunction(
          pErrnoLocation,
          'pointer',
          [],
        );
        return true;
      }
      case 'darwin':
      case 'freebsd':
      case 'qnx':
      case 'windows':
      case 'barebone':
      default:
        return false;
    }
  }
}
