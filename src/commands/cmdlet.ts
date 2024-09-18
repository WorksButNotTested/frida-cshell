import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const DELETE_CHAR: string = '#';

export abstract class CmdLet {
  public abstract readonly category: string;
  public abstract readonly name: string;
  public abstract readonly help: string;
  public readonly visible: boolean = true;
  public abstract usage(): Var;
  public abstract runSync(tokens: Token[]): Var;
  public async run(tokens: Token[]): Promise<Var> {
    return this.runSync(tokens);
  }
  public isSupported(): boolean {
    return true;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public transform<T extends any[]>(
    tokens: Token[],
    operations: { [K in keyof T]: (token: Token) => T[K] | null },
  ): T | null {
    if (tokens.length !== operations.length) return null;
    const result = operations.map((operation, index) =>
      operation(tokens[index] as Token),
    );
    if (result.some(v => v === null)) {
      return null;
    } else {
      return result as T;
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public transformOptional<M extends any[], O extends any[]>(
    tokens: Token[],
    madatory: { [K in keyof M]: (token: Token) => M[K] | null },
    optional: { [K in keyof O]: (token: Token) => O[K] | null },
  ): [M, { [K in keyof O]: O[K] | null }] | null {
    if (tokens.length < madatory.length) return null;
    if (tokens.length > madatory.length + optional.length) return null;

    const mVars = madatory.map((operation, index) =>
      operation(tokens[index] as Token),
    );

    let failed = false;
    const oVars = optional.map((operation, index) => {
      const token = tokens[index + madatory.length];
      if (token === undefined) return null;
      const result = operation(token);
      if (result === null) failed = true;
      return result;
    });

    if (failed) return null;

    if (mVars.some(v => v === null)) {
      return null;
    } else {
      return [mVars as M, oVars as O];
    }
  }

  protected parseVar(token: Token): Var | null {
    if (token === null) return null;
    return token.toVar();
  }

  protected parseLiteral(token: Token): string | null {
    if (token === null) return null;
    return token.getLiteral();
  }

  protected parseWidth(token: Token): number | null {
    const literal = token.getLiteral();
    switch (literal) {
      case '1':
        return 1;
      case '2':
        return 2;
      case '4':
        return 4;
      case '8':
        return 8;
      default:
        return null;
    }
  }

  protected parseDelete(token: Token): string | null {
    const literal = token.getLiteral();
    if (literal !== DELETE_CHAR) return null;
    return literal;
  }
}
