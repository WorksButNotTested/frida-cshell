import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Format } from '../../misc/format.js';
import { Var } from '../../vars/var.js';
import { Regex } from '../../misc/regex.js';

export class SymCmdLet extends CmdLetBase {
  name = 'sym';
  category = 'memory';
  help = 'look up a symbol information';

  private static readonly USAGE: string = `Usage: sym

sym [mod!]name - looks up a symbol based upon a glob
  mod   a glob for the module name
  name  a glob for the symbol name

sym name - display address information for a named symbol
  name   the name of the symbol to lookup

sym addr - display symbol information associated with an address
  addr   the address of the symbol to lookup`;

  public runSync(tokens: Token[]): Var {
    const retWithAddress = this.runShowAddress(tokens);
    if (retWithAddress !== null) return retWithAddress;

    const retWithWildCard = this.runShowNamed(tokens);
    if (retWithWildCard !== null) return retWithWildCard;

    return this.usage();
  }

  private runShowAddress(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar]);
    if (vars === null) return null;
    const [v0] = vars as [Var];

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
    const name = `${prefix}${debug.name}`;
    Output.writeln(
      `${Output.green(name.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(debug.address))}`,
    );
    if (debug.fileName !== null && debug.lineNumber !== null) {
      if (debug.fileName.length !== 0 && debug.lineNumber !== 0) {
        Output.writeln(
          `\t${Output.blue(debug.fileName)}:${Output.blue(debug.lineNumber.toString())} `,
        );
      }
    }
  }

  private splitName(name: string): [RegExp, RegExp] | null {
    const fileNameRegex =
      /^((?<module>[[\]?!*\w .-]+?)!)?(?<symbol>[[?*a-zA-Z_][[\]?!*a-zA-Z0-9_]*)$/;
    const m = name.match(fileNameRegex);
    if (m === null) return null;

    const g = m.groups;
    if (g === undefined) return null;

    const result = [g['module'], g['symbol']].map(s =>
      s === undefined ? Regex.MatchAll : Regex.globToRegex(s),
    );

    if (result.some(r => r === null)) return null;

    return result as [RegExp, RegExp];
  }

  private runShowNamed(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseLiteral]);
    if (vars === null) return null;
    const [name] = vars as [string];

    if (Regex.isGlob(name)) {
      const regexes = this.splitName(name);
      if (regexes === null) return null;
      const [moduleRegex, symbolRegex] = regexes;

      const modules = Process.enumerateModules().filter(m =>
        m.name.match(moduleRegex),
      );

      if (modules.length === 0) {
        Output.writeln('No modules found');
        return Var.ZERO;
      }

      const exports = modules
        .map(m =>
          m
            .enumerateExports()
            .filter(s => s.name.match(symbolRegex))
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
            .filter(s => s.name.match(symbolRegex))
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

      Array.from(all, ([key, value], index) =>
        [
          `${index.toString().padStart(3, ' ')}:`,
          Output.green(key.padEnd(40, '.')),
          Output.yellow(Format.toHexString(value.address)),
          `[${Output.blue(value.type)}]`,
        ].join(' '),
      ).forEach(s => Output.writeln(s, true));

      const values = Array.from(dict.values());
      if (values.length === 1) {
        const value = values[0] as {
          name: string;
          type: string;
          address: NativePointer;
        };
        return new Var(
          uint64(value.address.toString()),
          `Symbol: ${value.name}`,
        );
      } else {
        return Var.ZERO;
      }
    } else {
      const address = Module.findGlobalExportByName(name);
      if (address !== null) {
        Output.writeln(
          `${Output.green(name.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(address))}`,
        );
        return new Var(uint64(address.toString()), `Symbol: ${name}`);
      }

      const debug = DebugSymbol.fromName(name);
      if (!debug.address.isNull()) {
        this.printDebugSymbol(debug);
        return new Var(uint64(debug.address.toString()), `Symbol: ${name}`);
      }

      Output.writeln(`Symbol ${Output.bold(name)} not found`);
      return Var.ZERO;
    }
  }

  public usage(): Var {
    Output.writeln(SymCmdLet.USAGE);
    return Var.ZERO;
  }
}
