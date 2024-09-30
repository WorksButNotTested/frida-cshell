import { Output } from '../io/output.js';

export class Macro {
  private readonly _name: string;
  private readonly _commands: string[] = [];

  constructor(name: string, commands: string[]) {
    this._name = name;
    this._commands = commands;
  }

  public get name(): string {
    return this._name;
  }

  public get commands(): string[] {
    return this._commands;
  }

  public toString(): string {
    return this._commands
      .map(l => Output.writeln(`  - ${Output.yellow(l)}`))
      .join('\n');
  }
}

export class Macros {
  private static map: Map<string, Macro> = new Map<string, Macro>();

  public static get(name: string): Macro | null {
    return this.map.get(name) ?? null;
  }

  public static set(macro: Macro) {
    this.map.set(macro.name, macro);
  }

  public static delete(name: string): Macro | null {
    const macro = this.map.get(name);
    if (macro === undefined) return null;
    this.map.delete(name);
    return macro;
  }

  public static all(): Macro[] {
    return Array.from(this.map.entries())
      .sort(([k1, _v1], [k2, _v2]) => k1.localeCompare(k2))
      .map(([k, v]) => v);
  }
}
