import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Format } from '../misc/format.js';
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

  public run(tokens: Token[]): Var {
    const retWithAddress = this.runWithAddress(tokens);
    if (retWithAddress !== null) return retWithAddress;

    const retWithWildCard = this.runWithWildcard(tokens);
    if (retWithWildCard !== null) return retWithWildCard;

    const retWithName = this.runWithName(tokens);
    if (retWithName !== null) return retWithName;

    return this.usage();
  }

  private runWithAddress(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const v0 = t0.toVar();
    if (v0 === null) return null;

    const address = v0.toPointer();

    const debug = DebugSymbol.fromAddress(address);
    if (!debug.address.isNull() && debug.name !== null) {
      this.printDebugSymbol(debug);
      return v0;
    }

    Output.writeln(
      `No symbol found at address: ${Format.toHexString(address)}`,
    );
    return v0;
  }

  private printDebugSymbol(debug: DebugSymbol) {
    const prefix = debug.moduleName === null ? '' : `${debug.moduleName}!`;
    Output.writeln(
      `Debug Symbol: ${prefix}${debug.name} found at ${Format.toHexString(debug.address)}`,
    );
    if (debug.fileName !== null && debug.lineNumber !== null) {
      if (debug.fileName.length !== 0 && debug.lineNumber !== 0) {
        Output.writeln(`\t${debug.fileName}:${debug.lineNumber} `);
      }
    }
  }

  private runWithWildcard(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();

    const specialRegex = /[[\]?!*]/;
    if (!specialRegex.test(name)) return null;

    const fileNameRegex =
      /^((?<module>[[\]?!*\w .-]+?)!)?(?<symbol>[[?*a-zA-Z_][[\]?!*a-zA-Z0-9_]*)$/;
    const m = name.match(fileNameRegex);
    if (m === null) return null;

    const g = m.groups;
    if (g === undefined) return null;

    const module = g['module'] ?? null;
    const symbol = g['symbol'] ?? null;

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
        `${index.toString().padStart(3, ' ')}: ${Output.green(key.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(value.address))} [${Output.blue(value.type)}]`,
    ).forEach(s => Output.writeln(s));

    return Var.ZERO;
  }

  private globToRegex(glob: string | null): RegExp {
    if (glob === null) return /^.*$/;

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

  private runWithName(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const name = t0.getLiteral();

    const address = Module.findExportByName(null, name);
    if (address !== null) {
      Output.writeln(`Export: ${name} found at ${Format.toHexString(address)}`);
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

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }
}
