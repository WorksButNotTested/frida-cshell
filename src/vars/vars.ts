import { Var } from './var.js';

export class Vars {
  public static readonly RET_NAME = 'ret';

  private static map: Map<string, Var> = new Map<string, Var>();

  private constructor() {}

  public static getRet(): Var {
    return this.get(this.RET_NAME) ?? Var.ZERO;
  }

  public static setRet(val: Var) {
    this.push(this.RET_NAME, val);
  }

  public static push(name: string, val: Var) {
    if (!this.isNameValid(name))
      throw new Error(`variable name '${name}' is invalid`);
    this.map.set(name, val);
  }

  public static get(name: string): Var | undefined {
    if (!this.isNameValid(name)) return undefined;
    return this.map.get(name);
  }

  public static pop(name: string): Var | undefined {
    const val = this.map.get(name);
    if (val === undefined) return undefined;
    this.map.delete(name);
    return val;
  }

  public static all(): [string, Var][] {
    return Array.from(this.map.entries())
      .filter(([k, _]) => k !== this.RET_NAME)
      .sort(([k1, _v1], [k2, _v2]) => k1.localeCompare(k2));
  }

  private static isNameValid(name: string): boolean {
    const nameRegex = '^[a-zA-Z_][a-zA-Z0-9_]*$';
    if (name.match(nameRegex) === null) {
      return false;
    }
    return true;
  }
}
