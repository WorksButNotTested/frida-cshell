import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Util } from '../misc/util.js';
import { Var } from '../vars/var.js';

const USAGE: string = `Usage: sym

sym [mod!]name - looks up a symbol based upon a glob
  mod   a glob for the module name
  name  a glob for the symbol name

sym name - display address information for a named symbol
  name   the name of the symbol to lookup

sym addr - display symbol information associated with an address
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
    const prefix = debug.moduleName === null ? '' : `${debug.moduleName}!`;
    Output.writeln(
      `Debug Symbol: ${prefix}${debug.name} found at ${Util.toHexString(debug.address)}`,
    );
    if (debug.fileName !== null && debug.lineNumber !== null) {
      if (debug.fileName.length !== 0 && debug.lineNumber !== 0) {
        Output.writeln(`\t${debug.fileName}:${debug.lineNumber} `);
      }
    }
  }

  private runWithName(tokens: Token[]): Var | undefined {
    if (tokens.length !== 1) return undefined;

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

  private globToRegex(glob: string | undefined): RegExp {
    if (glob === undefined) return /^.*$/;

    const escaped = glob.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = escaped
      .replace(/\\\*/g, '.*')
      .replace(/\\\?/g, '.')
      .replace(/\\\[/g, '[')
      .replace(/\\\]/g, ']')
      .replace(/\[!(.*?)]/g, (match, chars) => {
        return '[^' + chars + ']';
      });
    return new RegExp(`^${regex}$`);
  }

  private runWithWildcard(tokens: Token[]): Var | undefined {
    if (tokens.length !== 1) return undefined;

    const name = tokens[0]?.getLiteral();
    if (name === undefined) return undefined;

    const specialRegex = /[[\]?!*]/;
    if (!specialRegex.test(name)) return undefined;

    const fileNameRegex =
      /^((?<module>[[\]?!*\w .-]+?)!)?(?<symbol>[[?*a-zA-Z_][[\]?!*a-zA-Z0-9_]*)$/;
    const m = name.match(fileNameRegex);
    if (m === null) return undefined;

    const g = m.groups;
    if (g === undefined) return undefined;

    const module = g['module'];
    const symbol = g['symbol'];

    Output.writeln(`module: ${module}`, true);
    Output.writeln(`symbol: ${symbol}`, true);

    const modRegex = this.globToRegex(module);

    const modules = Process.enumerateModules().filter(m =>
      m.name.match(modRegex),
    );

    if (modules.length === 0) {
      Output.writeln('No modules found');
      return Var.ZERO;
    }

    const symRegex = this.globToRegex(symbol);

    const exports = modules
      .map(m =>
        m
          .enumerateExports()
          .filter(s => s.name.match(symRegex))
          .map(s => ({
            name: `${m.name}!${s.name}`,
            type: 'E',
            address: s.address,
          })),
      )
      .flat();

    const symbols = modules
      .map(m =>
        m
          .enumerateSymbols()
          .filter(s => s.name.match(symRegex))
          .map(s => ({
            name: `${m.name}!${s.name}`,
            type: 'D',
            address: s.address,
          })),
      )
      .flat();

    const dict = new Map(exports.map(s => [s.name, s]));

    symbols.forEach(s => {
      if (!dict.has(s.name)) {
        dict.set(s.name, s);
      }
    });

    const all = Array.from(dict.entries()).sort((a, b) =>
      a[0].localeCompare(b[0]),
    );

    Array.from(
      all,
      ([key, value], index) =>
        `${index.toString().padStart(3, ' ')}: ${Output.green(key.padEnd(40, '.'))} ${Output.yellow(Util.toHexString(value.address))} [${Output.blue(value.type)}]`,
    ).forEach(s => Output.writeln(s));

    return Var.ZERO;
  }

  private runWithAddress(tokens: Token[]): Var | undefined {
    if (tokens.length !== 1) return undefined;

    const t0 = tokens[0]?.toVar();
    if (t0 === undefined) return undefined;

    const address = t0.toPointer();
    if (address === undefined) return undefined;

    const debug = DebugSymbol.fromAddress(address);
    if (!debug.address.isNull() && debug.name !== null) {
      this.printDebugSymbol(debug);
      return t0;
    }

    Output.writeln(`No symbol found at address: ${Util.toHexString(address)}`);
    return t0;
  }

  public run(tokens: Token[]): Var {
    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== undefined) return retWithAddress;

    const retWithWildCard = this.runWithWildcard(tokens);
    if (retWithWildCard !== undefined) return retWithWildCard;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== undefined) return retWithName;

    return this.usage();
  }
}
