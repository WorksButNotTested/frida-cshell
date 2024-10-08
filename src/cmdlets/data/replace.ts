import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Format } from '../../misc/format.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

interface Replacement {
  dest: Var;
  src: Var;
}

export class ReplaceCmdLet extends CmdLetBase {
  name = 'replace';
  category = 'data';
  help =
    'replace a function with another implementation (returns the address of the trampoline)';

  private byIndex: Map<number, Replacement> = new Map<number, Replacement>();

  private getNextFreeIndex(): number {
    let idx = 1;
    while (true) {
      if (!this.byIndex.has(idx)) return idx;
      idx++;
    }
  }

  private static readonly USAGE: string = `Usage: replace

replace dest src - replace function
  dest   the address/symbol to replace
  src    the address/symbol to replace with`;

  public runSync(tokens: Token[]): Var {
    const retDelete = this.runDelete(tokens);
    if (retDelete !== null) return retDelete;

    const retCreate = this.runCreate(tokens);
    if (retCreate !== null) return retCreate;

    const retShow = this.runShow(tokens);
    if (retShow !== null) return retShow;

    return this.usage();
  }

  public runDelete(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseIndex, this.parseDelete]);
    if (vars === null) return null;
    const [index, _] = vars as [number, string];
    const replacement = this.byIndex.get(index);
    if (replacement === undefined) {
      Output.writeln(`replacement #${index} not found`);
      return Var.ZERO;
    }

    Output.writeln(Output.blue('deleting replacement:'));
    this.printReplacement(index, replacement);
    this.byIndex.delete(index);
    Interceptor.revert(replacement.dest.toPointer());
    return Var.ZERO;
  }

  public runCreate(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseVar, this.parseVar]);
    if (vars === null) return null;
    const [destVar, srcVar] = vars as [Var, Var];

    const dest = destVar.toPointer();
    const src = srcVar.toPointer();

    try {
      const index = this.getNextFreeIndex();
      const replacement = { dest: destVar, src: srcVar };
      this.printReplacement(index, replacement);
      this.byIndex.set(index, replacement);
      const trampoline = Interceptor.replaceFast(dest, src);
      Output.writeln(Output.blue('created replacement:'));
      return new Var(uint64(trampoline.toString()));
    } catch (error) {
      throw new Error(
        `failed to replace ${Format.toHexString(dest)} with ${Format.toHexString(src)}, ${error}`,
      );
    }
  }

  public runShow(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    Output.writeln(Output.blue('replacements:'));
    this.byIndex.forEach((replacement, index) => {
      this.printReplacement(index, replacement);
    });
    return Var.ZERO;
  }

  private printReplacement(index: number, replacement: Replacement) {
    const idxString = Output.green(`#${index.toString()}.`.padEnd(4, ' '));
    const destString = `dest: ${Output.blue(replacement.dest.getLiteral())}`;
    const srcString = `src: ${Output.blue(replacement.src.getLiteral())}`;
    Output.writeln(`${idxString} ${destString} -> ${srcString}`);
  }

  public usage(): Var {
    Output.writeln(ReplaceCmdLet.USAGE);
    return Var.ZERO;
  }
}
