import { BpType, Bps } from '../bps.js';
import { CmdLet, CmdLetEdit } from '../cmdlet.js';
import { Input } from '../input.js';
import { Output } from '../output.js';
import { Token } from '../token.js';
import { Util } from '../util.js';
import { Var } from '../var.js';

const DELETE_CHAR: string = '#';

const BP_USAGE: string = `Usage: v
@ - show all breakpoints

@ addr - display a breakpoint
  addr    the address of the breakpoint to display

@ addr ${DELETE_CHAR} - delete a breakpoint
  addr    the address of the breakpoint to delete
`;

export class BpCmdLet extends CmdLet {
  name = '@';
  category = 'breakpoints';
  help = 'breakpoint management';

  public usage(): Var {
    Output.write(BP_USAGE);
    return Var.ZERO;
  }

  private runWithAddressAndHash(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const value = tokens[0]?.toVar();
    if (value === undefined) return undefined;

    const literal = tokens[1]?.getLiteral();
    if (literal === undefined) return undefined;

    if (literal != DELETE_CHAR) return undefined;

    if (Bps.delete(value) === undefined) {
      throw new Error(
        `No breakpoint at ${Util.toHexString(value.toPointer())}`,
      );
    }
    return value;
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const token = tokens[0];
    if (token === undefined) return undefined;

    const value = token.toVar();
    if (value === undefined) return undefined;

    const literal = token.getLiteral();

    const bp = Bps.get(value);
    if (bp === undefined)
      throw new Error(`No breakpoint found at ${Util.toHexString(value.toPointer())} (${literal})`,)

    Output.writeln(
      `${Util.toHexString(value.toPointer())}: ${bp.toString()}`,
    );

    return value;
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Output.writeln('Breakpoints:');

    for (const bp of Bps.all()) {
      Output.writeln(bp.toString());
    }
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithAddressAndHash = this.runWithAddressAndHash(tokens);
    if (retWithAddressAndHash !== undefined) return retWithAddressAndHash;

    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }
}

abstract class TypedBpCmdLet extends CmdLet implements CmdLetEdit {
  public abstract readonly bpType: BpType;
  
  category = 'breakpoints';
  
  public usage(): Var {
    const INSN_BP_USAGE: string = `Usage: ${this.name}
${this.name} addr - create, or modify an ${this.bpType} breakpoint
   addr    the address of the breakpoint to manage

${this.name} addr hits - create or modify an ${this.bpType} breakpoint to fire a set number of times
   addr    the address of the breakpoint to manage
   count   the number of times the breakpoint should fire
`;
    Output.write(INSN_BP_USAGE);
    return Var.ZERO;
  }

  private setBreakpoint(value: Var, literal: string, count: number) {
    const bp = Bps.get(value);
    if (bp !== undefined) {
      Output.writeln(
        `${Util.toHexString(value.toPointer())}: ${bp.toString()}`,
      );
    }

    Output.writeln(
      `Setting ${this.bpType} breakpoint at ${Util.toHexString(value.toPointer())} (${literal})`,
    );
    Bps.add(this.bpType, value, literal, count);
    Input.setEdit(this);
  }

  private runWithAddressAndCount(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const token = tokens[0];
    if (token === undefined) return undefined;

    const value = token.toVar();
    if (value === undefined) return undefined;

    const literal = token.getLiteral();

    const count = tokens[1]?.toVar();
    if (count === undefined) return undefined;

    this.setBreakpoint(value, literal, count.toU64().toNumber());

    return value;
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const token = tokens[0];
    if (token === undefined) return undefined;

    const value = token.toVar();
    if (value === undefined) return undefined;

    const literal = token.getLiteral();

    this.setBreakpoint(value, literal, -1);
    return value;
  }

  public run(tokens: Token[]): Var {
    const retWithAddressAndCount = this.runWithAddressAndCount(tokens);
    if (retWithAddressAndCount !== undefined) return retWithAddressAndCount;

    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    return this.usage();
  }

  addCommandLine(line: string) {
    Bps.addCommandLine(line);
  }

  done() {
    Bps.done();
  }

  abort() {
    Bps.abort();
  }
}

export class InsnBpCmdLet extends TypedBpCmdLet {
  name = '@i';
  bpType = BpType.Instruction;
  help = `${this.bpType} breakpoint`;
}