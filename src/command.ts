import { CmdLets } from './cmdlets.js';
import { Output } from './output.js';
import { Util } from './util.js';
import { Var } from './var.js';
import { Token } from './token.js';

export class Command {
  private static executeAddress(address: NativePointer, tokens: Token[]): Var {
    const ptrs: Var[] = [];
    const args: NativePointer[] = [];
    for (const token of tokens) {
      const p = token.toVar();
      if (p === undefined) {
        throw new Error(`Failed to parse token: ${token.getLiteral()}`);
      }

      ptrs.push(p);
      args.push(p.toPointer());
    }

    args.forEach((param, index) => {
      Output.writeln(
        `\t${index}: ${Util.toHexString(param)} ${Util.toDecString(param)}`,
        true,
      );
    });

    const func = new NativeFunction(address, 'pointer', [
      'pointer',
      'pointer',
      'pointer',
      'pointer',
      'pointer',
      'pointer',
      'pointer',
      'pointer',
    ]);

    const ret = func(
      args[0] ?? ptr(0),
      args[1] ?? ptr(0),
      args[2] ?? ptr(0),
      args[3] ?? ptr(0),
      args[4] ?? ptr(0),
      args[5] ?? ptr(0),
      args[6] ?? ptr(0),
      args[7] ?? ptr(0),
    );

    return new Var(uint64(ret.toString()));
  }

  public static run(tokens: Token[]): Var {
    for (const [index, token] of tokens.entries()) {
      const p = token.toVar();
      if (p === undefined) {
        Output.writeln(
          `${index.toString().padStart(3, ' ')}: ${token.getLiteral().padStart(20)} - literal`,
          true,
        );
      } else {
        Output.writeln(
          `${index.toString().padStart(3, ' ')}: ${token.getLiteral().padStart(20)} - ${p}`,
          true,
        );
      }
    }

    const t0 = tokens[0];
    if (t0 === undefined) throw new Error('Failed to tokenize command');

    const cmdlet = CmdLets.getByName(t0.getLiteral());
    if (cmdlet === undefined) {
      const addr = t0.toVar()?.toPointer();
      if (addr === undefined) {
        throw new Error(
          'Request was not understood as an internal command or a detected symbol',
        );
      }
      return this.executeAddress(addr, tokens.slice(1));
    } else {
      return cmdlet.run(tokens.slice(1));
    }
  }
}
