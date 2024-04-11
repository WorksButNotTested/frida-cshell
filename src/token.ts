import { Vars } from './vars.js';
import { Numeric } from './numeric.js';
import { Var } from './var.js';
import { Regs } from './regs.js';

export class Token {
  private readonly value: string;

  public constructor(value: string) {
    this.value = value;
  }

  public getLiteral(): string {
    return this.value;
  }

  public toVar(): Var | undefined {
    if (
      this.value.length > 1 &&
      this.value.startsWith('"') &&
      this.value.endsWith('"')
    )
      return new Var(this.value.slice(1, this.value.length - 1));

    const num = Numeric.parse(this.value);
    if (num !== undefined) return new Var(num);

    if (this.value.charAt(0) === '$')
      return Regs.get(this.value.slice(1));

    const v = Vars.get(this.value);
    if (v !== undefined) return v;

    const address = Module.findExportByName(null, this.value);
    if (address) {
      return new Var(uint64(address.toString()));
    }

    const param = DebugSymbol.fromName(this.value);
    if (!param.address.isNull())
      return new Var(uint64(param.address.toString()));

    return undefined;
  }
}
