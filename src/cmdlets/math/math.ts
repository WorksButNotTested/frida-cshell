import { CmdLet } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

abstract class BinaryOpCmdLet extends CmdLet {
  category = 'math';

  private static readonly HEX_LABEL: string = 'HEXADECIMAL';
  private static readonly DEC_LABEL: string = 'DECIMAL';

  protected abstract OPERATION: string;
  protected abstract op(op0: UInt64, op1: UInt64): UInt64;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseVar, this.parseVar]);
    if (vars === null) return this.usage();
    const [v0, v1] = vars as [Var, Var];

    const op0 = v0.toU64();
    const op1 = v1.toU64();
    try {
      return new Var(this.op(op0, op1));
    } catch (error) {
      throw new Error(
        `failed to ${this.OPERATION} ${Format.toHexString(op0)} and ${Format.toHexString(op1)}, ${error}`,
      );
    }
  }

  public usage(): Var {
    const usage: string = `Usage: ${this.name}

${this.name} op1 op2 - ${this.OPERATION} two values together
  op1   the first operand on which to perform the operation
  op2   the second operand on which to perform the operation`;
    Output.writeln(usage);
    return Var.ZERO;
  }

  protected output(op0: UInt64, op1: UInt64, val: UInt64) {
    const h0 = Format.toHexString(op0);
    const h1 = Format.toHexString(op1);
    const hv = Format.toHexString(val);
    const hMax = [
      BinaryOpCmdLet.HEX_LABEL,
      BinaryOpCmdLet.DEC_LABEL,
      h0,
      h1,
      hv,
    ]
      .map(x => x.length)
      .reduce((max, curr) => Math.max(max, curr));

    const d0 = Format.toDecString(op0);
    const d1 = Format.toDecString(op1);
    const dv = Format.toDecString(val);
    const dMax = [
      BinaryOpCmdLet.HEX_LABEL,
      BinaryOpCmdLet.DEC_LABEL,
      d0,
      d1,
      dv,
    ]
      .map(x => x.length)
      .reduce((max, curr) => Math.max(max, curr));

    const pad = ' '.repeat(this.name.length);
    const hLine = Output.bold('-'.repeat(this.name.length + hMax + 1));
    const dLine = Output.bold('-'.repeat(this.name.length + dMax + 1));
    const gap = ' '.repeat(5);

    Output.writeln();
    Output.writeln(
      `${pad} ${BinaryOpCmdLet.HEX_LABEL.padStart(hMax, ' ')}${gap}${pad} ${BinaryOpCmdLet.DEC_LABEL.padStart(dMax, ' ')}`,
    );
    Output.writeln(
      `${pad} ${Output.blue(h0.padStart(hMax, ' '))}${gap}${pad} ${Output.blue(d0.padStart(dMax, ' '))}`,
    );
    Output.writeln(
      `${this.name} ${Output.blue(h1.padStart(hMax, ' '))}${gap}${this.name} ${Output.blue(d1.padStart(dMax, ' '))}`,
    );
    Output.writeln(`${hLine}${gap}${dLine}`);
    Output.writeln(
      `${pad} ${Output.green(hv.padStart(hMax, ' '))}${gap}${pad} ${Output.green(dv.padStart(dMax, ' '))}`,
    );
    Output.writeln(`${hLine}${gap}${dLine}`);
    Output.writeln();
  }
}

abstract class UnaryOpCmdLet extends CmdLet {
  category = 'math';

  private static readonly HEX_LABEL: string = 'HEXADECIMAL';
  private static readonly DEC_LABEL: string = 'DECIMAL';

  protected abstract OPERATION: string;
  protected abstract op(op0: UInt64): UInt64;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return this.usage();
    const [v0] = vars as [Var];

    const op = v0.toU64();

    try {
      return new Var(this.op(op));
    } catch (error) {
      throw new Error(
        `failed to ${this.OPERATION} ${Format.toHexString(op)}, ${error}`,
      );
    }
  }

  public usage(): Var {
    const usage: string = `Usage: ${this.name}

${this.name} op - perform a ${this.OPERATION} operation on an operand
  op   the operand on which to operate`;
    Output.writeln(usage);
    return Var.ZERO;
  }

  protected output(op0: UInt64, val: UInt64) {
    const h0 = Format.toHexString(op0);
    const hv = Format.toHexString(val);
    const hMax = [UnaryOpCmdLet.HEX_LABEL, UnaryOpCmdLet.DEC_LABEL, h0, hv]
      .map(x => x.length)
      .reduce((max, curr) => Math.max(max, curr));

    const d0 = Format.toDecString(op0);
    const dv = Format.toDecString(val);
    const dMax = [UnaryOpCmdLet.HEX_LABEL, UnaryOpCmdLet.DEC_LABEL, d0, dv]
      .map(x => x.length)
      .reduce((max, curr) => Math.max(max, curr));

    const pad = ' '.repeat(this.name.length);
    const hLine = Output.bold('-'.repeat(this.name.length + hMax + 1));
    const dLine = Output.bold('-'.repeat(this.name.length + dMax + 1));
    const gap = ' '.repeat(5);

    Output.writeln();
    Output.writeln(
      `${pad} ${UnaryOpCmdLet.HEX_LABEL.padStart(hMax, ' ')}${gap}${pad} ${UnaryOpCmdLet.DEC_LABEL.padStart(dMax, ' ')}`,
    );
    Output.writeln(
      `${pad} ${Output.blue(h0.padStart(hMax, ' '))}${gap}${pad} ${Output.blue(d0.padStart(dMax, ' '))}`,
    );
    Output.writeln(`${hLine}${gap}${dLine}`);
    Output.writeln(
      `${pad} ${Output.green(hv.padStart(hMax, ' '))}${gap}${pad} ${Output.green(dv.padStart(dMax, ' '))}`,
    );
    Output.writeln(`${hLine}${gap}${dLine}`);
    Output.writeln();
  }
}

export class AddCmdLet extends BinaryOpCmdLet {
  name = '+';
  help = 'add two operands';

  protected OPERATION: string = 'add';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.add(op1);
    this.output(op0, op1, val);
    return val;
  }
}

export class SubCmdLet extends BinaryOpCmdLet {
  name = '-';
  help = 'subtract two operands';

  protected OPERATION: string = 'subtract';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.sub(op1);
    if (val.compare(op0) > 0)
      throw new Error(
        `numeric underflow performing: ${Format.toHexString(op0)} - ${Format.toHexString(op1)}`,
      );
    this.output(op0, op1, val);
    return val;
  }
}

export class MulCmdLet extends BinaryOpCmdLet {
  name = '*';
  help = 'multiply two operands';

  protected OPERATION: string = 'multiply';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const bi0 = BigInt(op0.toString());
    const bi1 = BigInt(op1.toString());
    const biv = bi0 * bi1;
    const bim = BigInt('0xffffffffffffffff');
    if (biv > bim)
      throw new Error(
        `numeric overflow performing: ${Format.toHexString(op0)} * ${Format.toHexString(op1)}`,
      );
    const val = uint64(biv.toString());
    this.output(op0, op1, val);
    return val;
  }
}

export class DivCmdLet extends BinaryOpCmdLet {
  name = '/';
  help = 'divide two operands';

  protected OPERATION: string = 'divide';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const bi0 = BigInt(op0.toString());
    const bi1 = BigInt(op1.toString());
    const biv = bi0 / bi1;
    const val = uint64(biv.toString());
    this.output(op0, op1, val);
    return val;
  }
}

export class OrCmdLet extends BinaryOpCmdLet {
  name = '|';
  help = 'or two operands';

  protected OPERATION: string = 'or';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.or(op1);
    this.output(op0, op1, val);
    return val;
  }
}

export class AndCmdLet extends BinaryOpCmdLet {
  name = '&';
  help = 'and two operands';

  protected OPERATION: string = 'and';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.and(op1);
    this.output(op0, op1, val);
    return val;
  }
}

export class XorCmdLet extends BinaryOpCmdLet {
  name = '^';
  help = 'xor two operands';

  protected OPERATION: string = 'xor';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.xor(op1);
    this.output(op0, op1, val);
    return val;
  }
}

export class ShrCmdLet extends BinaryOpCmdLet {
  name = '>>';
  help = 'shr op1 by op2';

  protected OPERATION: string = 'shr';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.shr(op1);
    this.output(op0, op1, val);
    return val;
  }
}

export class ShlCmdLet extends BinaryOpCmdLet {
  name = '<<';
  help = 'shl op1 by op2';

  protected OPERATION: string = 'shl';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.shl(op1);
    this.output(op0, op1, val);
    return val;
  }
}

export class EqCmdLet extends BinaryOpCmdLet {
  name = '==';
  help = 'test equality of op1 and op2';

  protected OPERATION: string = 'equals';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = uint64(op0.equals(op1) ? 1 : 0);
    this.output(op0, op1, val);
    return val;
  }
}

export class NeCmdLet extends BinaryOpCmdLet {
  name = '!=';
  help = 'test inequality of op1 and op2';

  protected OPERATION: string = 'not equals';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = uint64(op0.equals(op1) ? 0 : 1);
    this.output(op0, op1, val);
    return val;
  }
}

export class GreaterThanCmdLet extends BinaryOpCmdLet {
  name = '>';
  help = 'test if op1 greater than op2';

  protected OPERATION: string = 'greater than';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = uint64(op0.compare(op1) > 0 ? 1 : 0);
    this.output(op0, op1, val);
    return val;
  }
}

export class GreaterThanEqualsCmdLet extends BinaryOpCmdLet {
  name = '>=';
  help = 'test if op1 greater or equal to op2';

  protected OPERATION: string = 'greater than or equal to';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = uint64(op0.compare(op1) >= 0 ? 1 : 0);
    this.output(op0, op1, val);
    return val;
  }
}

export class LessThanCmdLet extends BinaryOpCmdLet {
  name = '<';
  help = 'test if op1 less than op2';

  protected OPERATION: string = 'less than';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = uint64(op0.compare(op1) < 0 ? 1 : 0);
    this.output(op0, op1, val);
    return val;
  }
}

export class LessThanEqualsCmdLet extends BinaryOpCmdLet {
  name = '<=';
  help = 'test if op1 less than or equal to op2';

  protected OPERATION: string = 'less than or equal to';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = uint64(op0.compare(op1) <= 0 ? 1 : 0);
    this.output(op0, op1, val);
    return val;
  }
}

export class NotCmdLet extends UnaryOpCmdLet {
  name = '~';
  help = 'bitwise not an operand';

  protected OPERATION: string = 'bitwise not';

  protected op(op: UInt64): UInt64 {
    const val = op.not();
    this.output(op, val);
    return val;
  }
}

export class EndianCmdLet extends UnaryOpCmdLet {
  name = '<>';
  help = 'reverse endian operation';

  protected OPERATION: string = 'reverse endian';

  public override runSync(tokens: Token[]): Var {
    if (tokens.length !== 2) return this.usage();

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];
    const width = this.getWidth(t0);
    const v1 = t1.toVar();

    if (width === null) return this.usage();
    if (v1 === null) return this.usage();

    const op = v1.toU64();
    try {
      return new Var(this.reverseEndian(width, op));
    } catch (error) {
      throw new Error(
        `failed to ${this.OPERATION} ${Format.toHexString(op)} of width ${Format.toHexString(width)}, ${error}`,
      );
    }
  }

  private getWidth(token: Token): number | null {
    const literal = token.getLiteral();
    switch (literal) {
      case '1':
        return 1;
      case '2':
        return 2;
      case '4':
        return 4;
      case '8':
        return 8;
      default:
        return null;
    }
  }

  private reverseEndian(width: number, op: UInt64): UInt64 {
    this.testRange(width, op);
    switch (width) {
      case 1: {
        this.output(op, op);
        return op;
      }
      case 2: {
        const b0 = op.and(uint64('0xff')).shl(8);
        const b1 = op.and(uint64('0xff00')).shr(8);
        const val = b0.or(b1);
        this.output(op, val);
        return val;
      }
      case 4: {
        const b0 = op.and(uint64('0xff')).shl(24);
        const b1 = op.and(uint64('0xff00')).shl(8);
        const b2 = op.and(uint64('0xff0000')).shr(8);
        const b3 = op.and(uint64('0xff000000')).shr(24);
        const val = [b0, b1, b2, b3].reduce((v, x) => v.or(x));
        this.output(op, val);
        return val;
      }
      case 8: {
        const b0 = op.and(uint64('0xff')).shl(56);
        const b1 = op.and(uint64('0xff00')).shl(40);
        const b2 = op.and(uint64('0xff0000')).shl(24);
        const b3 = op.and(uint64('0xff000000')).shl(8);
        const b4 = op.and(uint64('0xff00000000')).shr(8);
        const b5 = op.and(uint64('0xff0000000000')).shr(24);
        const b6 = op.and(uint64('0xff000000000000')).shr(40);
        const b7 = op.and(uint64('0xff000000000000')).shr(56);
        const val = [b0, b1, b2, b3, b4, b5, b6, b7].reduce((v, x) => v.or(x));
        this.output(op, val);
        return val;
      }
      default:
        throw new Error(`unsupported width: ${width}`);
    }
  }

  private testRange(width: number, op: UInt64) {
    switch (width) {
      case 1: {
        if (op.compare(uint64('0xff')) > 0) {
          throw new Error(
            `operand: ${op} is larger than ${width} bytes in length`,
          );
        }
        break;
      }
      case 2: {
        if (op.compare(uint64('0xffff')) > 0) {
          throw new Error(
            `operand: ${op} is larger than ${width} bytes in length`,
          );
        }
        break;
      }
      case 4: {
        if (op.compare(uint64('0xffffffff')) > 0) {
          throw new Error(
            `operand: ${op} is larger than ${width} bytes in length`,
          );
        }
        break;
      }
      case 8: {
        /*
         * 8 bytes is the maximum supported operand so it can't be out of range
         */
        break;
      }
      default:
        throw new Error(`unsupported width: ${width}`);
    }
  }

  public override op(_op0: UInt64): UInt64 {
    throw new Error('not implemented');
  }

  public override usage(): Var {
    const usage: string = `Usage: ${this.name}

${this.name} width val - ${this.OPERATION} of an operand
  width   the width of the operand (1, 2, 4 or 8)
  op      the operand on which to perform the operation`;
    Output.writeln(usage);
    return Var.ZERO;
  }
}

export class TrueCmdLet extends UnaryOpCmdLet {
  name = 'true';
  help = 'test operand for non-zero';

  protected OPERATION: string = 'test for non-zero';

  protected op(op: UInt64): UInt64 {
    const val = uint64(op.equals(uint64('0')) ? 0 : 1);
    this.output(op, val);
    return val;
  }
}

export class FalseCmdLet extends UnaryOpCmdLet {
  name = 'false';
  help = 'test operand for zero';

  protected OPERATION: string = 'test for zero';

  protected op(op: UInt64): UInt64 {
    const val = uint64(op.equals(uint64('0')) ? 1 : 0);
    this.output(op, val);
    return val;
  }
}
