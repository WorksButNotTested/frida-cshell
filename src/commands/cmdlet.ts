import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

export abstract class CmdLet {
  public abstract readonly category: string;
  public abstract readonly name: string;
  public abstract readonly help: string;
  public readonly visible: boolean = true;
  public readonly asynchronous: boolean = false;
  public abstract usage(): Var;
  public abstract run(tokens: Token[]): Var;
  public async runAsync(tokens: Token[]): Promise<Var> {
    throw new Error('not supported');
  }
  public isSupported(): boolean {
    return true;
  }
}

export interface CmdLetEdit {
  addCommandLine(line: string): void;
  done(): void;
  abort(): void;
}
