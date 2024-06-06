import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

abstract class BinaryOpCmdLet extends CmdLet {
  category = 'math';

  protected abstract OPERATION: string;
  protected abstract op(op0: UInt64, op1: UInt64): UInt64;

  public run(tokens: Token[]): Var {
    if (tokens.length !== 2) return this.usage();

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];
    const [v0, v1] = [t0.toVar(), t1.toVar()];

    if (v0 === null) return this.usage();
    if (v1 === null) return this.usage();

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
  op2   the second operand on which to perform the operation
`;
    Output.write(usage);
    return Var.ZERO;
  }

  protected output(op0: UInt64, op1: UInt64, val: UInt64) {
    const h0 = Format.toHexString(op0);
    const h1 = Format.toHexString(op1);
    const hv = Format.toHexString(val);
    const hMax = Math.max(Math.max(h0.length, h1.length), hv.length);

    const d0 = Format.toDecString(op0);
    const d1 = Format.toDecString(op1);
    const dv = Format.toDecString(val);
    const dMax = Math.max(Math.max(d0.length, d1.length), dv.length);

    const pad = ' '.repeat(this.name.length);
    const hLine = Output.bold('-'.repeat(this.name.length + hMax + 1));
    const dLine = Output.bold('-'.repeat(this.name.length + dMax + 1));
    const gap = ' '.repeat(5);

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

  protected abstract OPERATION: string;
  protected abstract op(op0: UInt64): UInt64;

  public run(tokens: Token[]): Var {
    if (tokens.length !== 1) return this.usage();

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return this.usage();

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
  op   the operand on which to operate
`;
    Output.write(usage);
    return Var.ZERO;
  }

  protected output(op0: UInt64, val: UInt64) {
    const h0 = Format.toHexString(op0);
    const hv = Format.toHexString(val);
    const hMax = Math.max(h0.length, hv.length);

    const d0 = Format.toDecString(op0);
    const dv = Format.toDecString(val);
    const dMax = Math.max(d0.length, dv.length);

    const pad = ' '.repeat(this.name.length);
    const hLine = Output.bold('-'.repeat(this.name.length + hMax + 1));
    const dLine = Output.bold('-'.repeat(this.name.length + dMax + 1));
    const gap = ' '.repeat(5);

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
