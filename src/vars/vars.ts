import { Var } from './var.js';

export class Vars {
  public static readonly RET_NAME = 'ret';

  private static map: Map<string, Var> = new Map<string, Var>();

  private constructor() {}

  public static set(name: string, val: Var) {
    if (!this.isNameValid(name))
      throw new Error(`variable name '${name}' is invalid`);
    this.map.set(name, val);
  }

  private static isNameValid(name: string): boolean {
    const nameRegex = '^[a-zA-Z_][a-zA-Z0-9_]*$';
    if (name.match(nameRegex) === null) {
      return false;
    }
    return true;
  }

  public static get(name: string): Var | null {
    if (!this.isNameValid(name)) return null;
    return this.map.get(name) ?? null;
  }

  public static delete(name: string): Var | null {
    if (!this.map.has(name)) return null;
    const val = this.map.get(name) as Var;
    this.map.delete(name);
    return val;
  }

  public static getRet(): Var {
    return this.get(this.RET_NAME) ?? Var.ZERO;
  }

  public static setRet(val: Var) {
    this.set(this.RET_NAME, val);
  }

  public static all(): [string, Var][] {
    return Array.from(this.map.entries())
      .filter(([k, _]) => k !== this.RET_NAME)
      .sort(([k1, _v1], [k2, _v2]) => k1.localeCompare(k2));
  }
}
