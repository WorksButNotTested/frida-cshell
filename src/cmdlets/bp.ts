import { CmdLet } from '../cmdlet.js';
import { Output } from '../output.js';
import { Token } from '../token.js';
import { Var } from '../var.js';

const DELETE_CHAR: string = '#';

const USAGE: string = `Usage: v
@ - show all breakpoints

@ addr - display a breakpoint
  addr    the address of the breakpoint to display

@ addr - create, display or modify a breakpoint
  addr    the address of the breakpoint to manage

@ addr ${DELETE_CHAR} - delete a breakpoint
  addr    the address of the breakpoint to delete
`;

export class BpCmdLet extends CmdLet {
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

    /* TODO - Delete here */
    return value;
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const value = tokens[0]?.toVar();
    if (value === undefined) return undefined;

    /* TODO - Create, display or modify here */
    return value;
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Output.writeln('Breakpoints:');
    
    /* TODO: Show breakpoints */
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
