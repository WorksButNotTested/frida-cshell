import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

export interface CmdLet {
  readonly name: string;
  category: string;
  help: string;
  visible: boolean;
  usage(): Var;
  runSync(tokens: Token[]): Var;
  run(tokens: Token[]): Promise<Var>;
  isSupported(): boolean;
}

export abstract class CmdLetBase implements CmdLet {
  private static readonly UNLIMITED_CHAR: string = '*';
  public static readonly NUM_CHAR: string = '#';
  public static readonly DELETE_CHAR: string = '#';
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
    mandatory: { [K in keyof M]: (token: Token) => M[K] | null }, // Fixed typo
    optional: { [K in keyof O]: (token: Token) => O[K] | null },
  ): [M, { [K in keyof O]: O[K] | null }] | null {
    if (tokens.length < mandatory.length) return null;
    if (tokens.length > mandatory.length + optional.length) return null;

    // Mandatory variables
    const mVars = mandatory.map((operation, index) =>
      operation(tokens[index] as Token),
    );

    let failed = false;

    // Optional variables
    const oVars = optional.map((operation, index) => {
      const token = tokens[index + mandatory.length];
      if (token === undefined) return null;
      const result = operation(token);
      if (result === null) failed = true;
      return result;
    });

    if (failed) return null;

    // If any mandatory variable is null, return null
    if (mVars.some(v => v === null)) {
      return null;
    } else {
      // Return both mandatory and optional variables
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

  protected parseString(token: Token): string | null {
    if (token === null) return null;
    return token.getString();
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
    if (literal !== CmdLetBase.DELETE_CHAR) return null;
    return literal;
  }

  protected parseNumberOrAll(token: Token): number | null {
    if (token.getLiteral() === CmdLetBase.UNLIMITED_CHAR) return -1;

    const v = token.toVar();
    if (v === null) return null;

    const hits = v.toU64().toNumber();
    return hits;
  }

  protected parseIndex(token: Token): number | null {
    const literal = token.getLiteral();
    if (literal.startsWith(CmdLetBase.NUM_CHAR))
      return CmdLetBase.parseIndexString(literal);

    const v = token.toVar();
    if (v === null) return null;
    return CmdLetBase.parseIndexString(v.getLiteral());
  }

  private static parseIndexString(literal: string): number | null {
    if (!literal.startsWith(CmdLetBase.NUM_CHAR)) return null;

    const numStr = literal.slice(1);
    const val = parseInt(numStr);

    if (isNaN(val)) return null;
    return val;
  }
}
