enum Base {
  Octal,
  Decimal,
  Hexadecimal,
  Invalid,
}

export class Numeric {
  private static getBase(val: string): Base {
    const hexWithPrefix = '^0[xX][0-9a-fA-F]+$';
    if (val.match(hexWithPrefix) !== null) return Base.Hexadecimal;

    const decimalWithPrefix = '^0[dD][0-9]+';
    if (val.match(decimalWithPrefix) !== null) return Base.Decimal;

    const octalWithPrefix = '^0[oO]?[0-7]+$';
    if (val.match(octalWithPrefix) !== null) return Base.Octal;

    const decimalWithoutPrefix = '^[0-9]+$';
    if (val.match(decimalWithoutPrefix) !== null) return Base.Decimal;

    const hexWithoutPrefix = '^[0-9a-fA-F]+$';
    if (val.match(hexWithoutPrefix) !== null) return Base.Hexadecimal;

    return Base.Invalid;
  }

  private static getBareString(val: string): string {
    const prefixRegex = '^0[oOdDxX]';
    if (val.match(prefixRegex) !== null) {
      return val.slice(2);
    } else {
      return val;
    }
  }

  public static parse(val: string): UInt64 | null {
    const stripped = val.split('`').join('');
    const bare = this.getBareString(stripped);

    const base = this.getBase(stripped);
    switch (base) {
      case Base.Octal:
        if (isNaN(parseInt(bare, 8))) return null;
        break;
      case Base.Decimal:
        if (isNaN(parseInt(bare, 10))) return null;
        break;
      case Base.Hexadecimal:
        if (isNaN(parseInt(bare, 16))) return null;
        break;
      case Base.Invalid:
        return null;
    }

    switch (base) {
      case Base.Octal: {
        const num = parseInt(bare, 8);
        if (!Number.isSafeInteger(num)) return null;
        return uint64(num);
      }
      case Base.Decimal:
        return uint64(bare);
      case Base.Hexadecimal:
        return uint64(`0x${bare}`);
    }

    return null;
  }
}
