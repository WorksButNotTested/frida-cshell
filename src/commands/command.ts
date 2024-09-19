import { CmdLets } from './cmdlets.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';
import { Token } from '../io/token.js';
import { CmdLet } from './cmdlet.js';

export class Command {
  public static async run(tokens: Token[]): Promise<Var> {
    const cmdlet = this.getCmdlet(tokens);
    if (cmdlet === null) {
      return this.runFunction(tokens);
    } else {
      return cmdlet.run(tokens.slice(1));
    }
  }

  public static runSync(tokens: Token[]): Var {
    const cmdlet = this.getCmdlet(tokens);
    if (cmdlet === null) {
      return this.runFunction(tokens);
    } else {
      return cmdlet.runSync(tokens.slice(1));
    }
  }

  private static getCmdlet(tokens: Token[]): CmdLet | null {
    if (tokens.length === 0) throw new Error('failed to tokenize command');
    const t0 = tokens[0] as Token;
    return CmdLets.getByName(t0.getLiteral());
  }

  private static runFunction(tokens: Token[]): Var {
    if (tokens.length === 0) throw new Error('failed to tokenize command');
    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) {
      throw new Error(
        'request was not understood as an internal command or a detected symbol',
      );
    }
    const addr = v0.toPointer();
    return this.executeAddress(addr, tokens.slice(1));
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
      Output.debug(
        [
          `\t${index}:`,
          Format.toHexString(param),
          Format.toDecString(param),
        ].join(' '),
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
