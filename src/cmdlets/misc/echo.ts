import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

export class EchoCmdLet extends CmdLetBase {
  name = 'echo';
  category = 'misc';
  help = 'toggle echo mode';

  public static echo: boolean = true;

  private static readonly USAGE: string = `Usage: echo
echo on - enable echo (default)

echo off - disable echo`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(tokens, [], [this.parseSwitch]);
    if (vars === null) return this.usage();
    const [, [state]] = vars as [[], [boolean | null]];
    if (state === null) {
      Output.writeln(
        `echo is [${EchoCmdLet.echo ? Output.green('on') : Output.red('off')}]`,
      );
      return Var.ZERO;
    }
    EchoCmdLet.echo = state;
    return Var.ZERO;
  }

  protected parseSwitch(token: Token): boolean | null {
    const literal = token.getLiteral();
    if (literal === 'on') return true;
    if (literal === 'off') return false;
    return null;
  }

  public usage(): Var {
    Output.writeln(EchoCmdLet.USAGE);
    return Var.ZERO;
  }
}
