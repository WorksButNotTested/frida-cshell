import { Token } from "./token.js";
import { Var } from "./var.js";

export abstract class CmdLet {
  public abstract readonly category: string;
  public abstract readonly name: string;
  public abstract readonly help: string;
  public readonly visible: boolean = true;
  public abstract usage(): Var;
  public abstract run(tokens: Token[]): Var;
}
