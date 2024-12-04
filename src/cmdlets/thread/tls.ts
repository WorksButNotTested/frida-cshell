import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';
import { Tls } from '../../tls/tls.js';

export class TlsCmdLet extends CmdLetBase {
  name = 'tls';
  category = 'thread';
  help = 'read the TLS pointer';

  private static readonly USAGE: string = `Usage: tls
tls - get the tls pointer`;

  public runSync(tokens: Token[]): Var {
    if (tokens.length > 0) {
      Output.writeln(TlsCmdLet.USAGE);
      return Var.ZERO;
    }

    const tls = Tls.getTls();
    return new Var(uint64(tls.toString()));
  }

  public override isSupported(): boolean {
    return Tls.isSupported();
  }

  public usage(): Var {
    Output.writeln(TlsCmdLet.USAGE);
    return Var.ZERO;
  }
}
