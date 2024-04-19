import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Util } from '../misc/util.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: sym

sym name - display address information for a named symbol
  name   the name of the symbol to lookup

sm addr - display symbol information associated with an address
  addr   the address of the symbol to lookup
`;

export class SymCmdLet extends CmdLet {
  name = 'sym';
  category = 'memory';
  help = 'look up a symbol information';

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private printDebugSymbol(debug: DebugSymbol) {
    const prefix = debug.moduleName == null ? '' : `${debug.moduleName}!`;
    Output.writeln(
      `Debug Symbol: ${prefix}${debug.name} found at ${Util.toHexString(debug.address)}`,
    );
    if (debug.fileName !== null && debug.lineNumber !== null) {
      if (debug.fileName.length != 0 && debug.lineNumber != 0) {
        Output.writeln(`\t${debug.fileName}:${debug.lineNumber} `);
      }
    }
  }

  private runWithName(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const address = Module.findExportByName(null, name);
    if (address !== null) {
      Output.writeln(`Export: ${name} found at ${Util.toHexString(address)}`);
      return new Var(uint64(address.toString()));
    }

    const debug = DebugSymbol.fromName(name);
    if (!debug.address.isNull()) {
      this.printDebugSymbol(debug);
      return new Var(uint64(debug.address.toString()));
    }

    Output.writeln(`Symbol ${name} not found`);
    return Var.ZERO;
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return undefined;

    const address = t0.toPointer();
    if (address === undefined) return undefined;

    const debug = DebugSymbol.fromAddress(address);
    if (!debug.address.isNull() && debug.name != null) {
      this.printDebugSymbol(debug);
      return t0;
    }

    Output.writeln(`No symbol found at address: ${Util.toHexString(address)}`);
    return t0;
  }

  public run(tokens: Token[]): Var {
    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    return this.usage();
  }
}
