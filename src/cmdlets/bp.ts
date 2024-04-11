import { Bps } from '../bps.js';
import { CmdLet, CmdLetEdit } from '../cmdlet.js';
import { Input } from '../input.js';
import { Output } from '../output.js';
import { Token } from '../token.js';
import { Util } from '../util.js';
import { Var } from '../var.js';

const DELETE_CHAR: string = '#';

const USAGE: string = `Usage: v
@ - show all breakpoints

@ addr - display a breakpoint
  addr    the address of the breakpoint to display

@ addr - create, display or modify a breakpoint
  addr    the address of the breakpoint to manage

@ addr hits - create, display or modify a breakpoint to fire a set number of times
  addr    the address of the breakpoint to manage
  count   the number of times the breakpoint should fire

@ addr ${DELETE_CHAR} - delete a breakpoint
  addr    the address of the breakpoint to delete
`;

export class BpCmdLet extends CmdLet implements CmdLetEdit {
  name = '@';
  category = 'breakpoints';
  help = 'breakpoint management';

  public usage(): Var {
    Output.write(USAGE);
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

  private setBreakpoint(value: Var, literal: string, count: number) {
    const bp = Bps.get(value);
    if (bp !== undefined) {
      Output.writeln(
        `${Util.toHexString(value.toPointer())}: ${bp.toString()}`,
      );
    }

    Output.writeln(
      `Setting breakpoint at ${Util.toHexString(value.toPointer())} (${literal})`,
    );
    Bps.add(value, literal, count);
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

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Output.writeln('Breakpoints:');

    for (const [v, bp] of Bps.all()) {
      Output.writeln(
        `${Output.bold(Util.toHexString(v.toPointer()))}: ${bp.toString()}`,
      );
    }
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithAddressAndHash = this.runWithAddressAndHash(tokens);
    if (retWithAddressAndHash !== undefined) return retWithAddressAndHash;

    const retWithAddressAndCount = this.runWithAddressAndCount(tokens);
    if (retWithAddressAndCount !== undefined) return retWithAddressAndCount;

    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

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
