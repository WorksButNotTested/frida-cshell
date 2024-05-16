import { CmdLets } from './cmdlets.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';
import { Token } from '../io/token.js';

export class Command {
  public static run(tokens: Token[]): Var {
    for (const [index, token] of tokens.entries()) {
      const p = token.toVar();
      if (p === null) {
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

    if (tokens.length === 0) throw new Error('failed to tokenize command');
    const t0 = tokens[0] as Token;

    const cmdlet = CmdLets.getByName(t0.getLiteral());
    if (cmdlet === null) {
      const v0 = t0.toVar();
      if (v0 === null) {
        throw new Error(
          'request was not understood as an internal command or a detected symbol',
        );
      }
      const addr = v0.toPointer();
      return this.executeAddress(addr, tokens.slice(1));
    } else {
      return cmdlet.run(tokens.slice(1));
    }
  }

  private static executeAddress(address: NativePointer, tokens: Token[]): Var {
    const ptrs: Var[] = [];
    const args: NativePointer[] = [];
    for (const token of tokens) {
      const p = token.toVar();
      if (p === null) {
        throw new Error(`failed to parse token: ${token.getLiteral()}`);
      }

      ptrs.push(p);
      args.push(p.toPointer());
    }

    args.forEach((param, index) => {
      Output.writeln(
        `\t${index}: ${Format.toHexString(param)} ${Format.toDecString(param)}`,
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
}
