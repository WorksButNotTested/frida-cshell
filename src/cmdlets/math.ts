import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

abstract class MathCmdLet extends CmdLet {
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
}

export class AddCmdLet extends MathCmdLet {
  name = '+';
  help = 'add two operands';

  protected OPERATION: string = 'add';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.add(op1);
    Output.writeln(
      `${Format.toHexString(op0)} + ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} + ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class SubCmdLet extends MathCmdLet {
  name = '-';
  help = 'subtract two operands';

  protected OPERATION: string = 'subtract';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.sub(op1);
    if (val.compare(op0) > 0)
      throw new Error(
        `numeric underflow performing: ${Format.toHexString(op0)} - ${Format.toHexString(op1)}`,
      );
    Output.writeln(
      `${Format.toHexString(op0)} - ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} - ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class MulCmdLet extends MathCmdLet {
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
    Output.writeln(
      `${Format.toHexString(op0)} * ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} * ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class DivCmdLet extends MathCmdLet {
  name = '/';
  help = 'divide two operands';

  protected OPERATION: string = 'divide';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const bi0 = BigInt(op0.toString());
    const bi1 = BigInt(op1.toString());
    const biv = bi0 / bi1;
    const val = uint64(biv.toString());
    Output.writeln(
      `${Format.toHexString(op0)} / ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} / ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class OrCmdLet extends MathCmdLet {
  name = '|';
  help = 'or two operands';

  protected OPERATION: string = 'or';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.or(op1);
    Output.writeln(
      `${Format.toHexString(op0)} | ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} | ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class AndCmdLet extends MathCmdLet {
  name = '&';
  help = 'and two operands';

  protected OPERATION: string = 'and';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.and(op1);
    Output.writeln(
      `${Format.toHexString(op0)} & ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} & ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class XorCmdLet extends MathCmdLet {
  name = '^';
  help = 'xor two operands';

  protected OPERATION: string = 'xor';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.xor(op1);
    Output.writeln(
      `${Format.toHexString(op0)} ^ ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} ^ ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class ShrCmdLet extends MathCmdLet {
  name = '>>';
  help = 'shr op1 by op2';

  protected OPERATION: string = 'shr';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.shr(op1);
    Output.writeln(
      `${Format.toHexString(op0)} >> ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} >> ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class ShlCmdLet extends MathCmdLet {
  name = '<<';
  help = 'shl op1 by op2';

  protected OPERATION: string = 'shl';

  protected op(op0: UInt64, op1: UInt64): UInt64 {
    const val = op0.shl(op1);
    Output.writeln(
      `${Format.toHexString(op0)} << ${Format.toHexString(op1)} = ${Format.toHexString(val)}`,
    );
    Output.writeln(
      `${Format.toDecString(op0)} << ${Format.toDecString(op1)} = ${Format.toDecString(val)}`,
    );
    return val;
  }
}

export class NotCmdLet extends CmdLet {
  name = '~';
  category = 'math';
  help = 'bitwise not';

  public usage(): Var {
    const usage: string = `Usage: not

not op - perform a bitwise not operation on an operand
  op   the operand on which to operate
`;
    Output.write(usage);
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    if (tokens.length !== 1) return this.usage();

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return this.usage();

    const op = v0.toU64();

    try {
      return new Var(op.not());
    } catch (error) {
      throw new Error(`failed to not ${Format.toHexString(op)}, ${error}`);
    }
  }
}
