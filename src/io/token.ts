import { Vars } from '../vars/vars.js';
import { Numeric } from '../misc/numeric.js';
import { Var } from '../vars/var.js';
import { Regs } from '../breakpoints/regs.js';

export class Token {
  private static isQuotedString(s: string): boolean {
    return (
      s.length > 1 &&
      s.startsWith('"') &&
      s.endsWith('"') &&
      s.slice(1, s.length - 1).indexOf('"') === -1
    );
  }

  private readonly value: string;

  public constructor(value: string) {
    this.value = value;
  }

  public getLiteral(): string {
    return this.value;
  }

  public getString(): string {
    if (Token.isQuotedString(this.value))
      return this.value.slice(1, this.value.length - 1);

    const v = Vars.get(this.value);
    if (v !== null) {
      const value = v.getLiteral();
      if (Token.isQuotedString(value)) {
        return value.slice(1, value.length - 1);
      } else {
        return v.getLiteral();
      }
    }

    return this.value;
  }

  public toVar(): Var | null {
    if (Token.isQuotedString(this.value))
      return new Var(this.value.slice(1, this.value.length - 1), this.value);

    const num = Numeric.parse(this.value);
    if (num !== null) return new Var(num, this.value);

    if (this.value.charAt(0) === '$') return Regs.get(this.value.slice(1));

    const v = Vars.get(this.value);
    if (v !== null) return v;

    const address = Module.findGlobalExportByName(this.value);
    if (address !== null) {
      return new Var(uint64(address.toString()), this.value);
    }

    const param = DebugSymbol.fromName(this.value);
    if (!param.address.isNull())
      return new Var(uint64(param.address.toString()), this.value);

    return null;
  }
}
