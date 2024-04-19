import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

export abstract class CmdLet {
  public abstract readonly category: string;
  public abstract readonly name: string;
  public abstract readonly help: string;
  public readonly visible: boolean = true;
  public abstract usage(): Var;
  public abstract run(tokens: Token[]): Var;
  public isSupported(): boolean {
    return true;
  }
}

export interface CmdLetEdit {
  addCommandLine(line: string): void;
  done(): void;
  abort(): void;
}
