import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

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
}
