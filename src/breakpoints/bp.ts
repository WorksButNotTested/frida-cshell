import { Command } from '../commands/command.js';
import { Input } from '../io/input.js';
import { Output } from '../io/output.js';
import { Parser } from '../io/parser.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';
import { Vars } from '../vars/vars.js';

export enum BpKind {
  Code = 'code',
  Memory = 'memory',
  Replacement = 'replacement',
}

export enum BpType {
  Instruction = 'instruction',
  FunctionEntry = 'function entry',
  FunctionExit = 'function exit',
  BlockTrace = 'block trace',
  CallTrace = 'call trace',
  UniqueBlockTrace = 'unique block trace',
  Coverage = 'coverage',
  MemoryRead = 'memory read',
  MemoryWrite = 'memory write',
  Replacement = 'replacement',
}

export abstract class Bp {
  abstract readonly type: BpType;
  abstract readonly kind: BpKind;
  abstract readonly supports_commands: boolean;
  public readonly index: number;

  public address: Var | null;
  public length: number = 0;
  public hits: number = -1;
  public conditions: string[] = [];
  public commands: string[] = [];

  protected constructor(
    index: number,
    address: Var | null,
    length: number | null,
    hits: number | null,
  ) {
    this.index = index;
    this.address = address;
    this.length = length ?? 0;
    this.hits = hits ?? -1;
  }

  public overlaps(bp: Bp): boolean {
    if (bp.address === null) return false;
    if (bp.length === 0) return false;
    if (this.address === null) return false;
    if (this.length === 0) return false;

    /* we cannot overlap with ourself */
    if (bp.index === this.index && bp.kind == this.kind) return false;

    const start = this.address.toPointer();

    if (start.add(this.length).compare(bp.address.toPointer()) <= 0)
      return false;
    if (start.compare(bp.address.toPointer().add(bp.length)) >= 0) return false;
    return true;
  }

  public compare(other: Bp): number {
    return this.index - other.index;
  }

  protected get literal(): string {
    return this.address?.getLiteral() ?? '';
  }

  protected runConditions(): boolean {
    if (this.conditions.length === 0) return true;

    if (!Output.getDebugging()) {
      Output.suppress(true);
    }
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      for (const condition of this.conditions) {
        if (condition.length === 0) continue;
        if (condition.charAt(0) === '#') continue;
        Output.writeln(`${Output.bold(Input.PROMPT)}${condition}`);
        const parser = new Parser(condition.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Input.prompt();
      Output.suppress(false);
    }

    if (Vars.getRet().compare(Var.ZERO) === 0) {
      return false;
    } else {
      return true;
    }
  }

  protected runCommands() {
    if (this.supports_commands === false) return;
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      for (const command of this.commands) {
        if (command.length === 0) continue;
        if (command.charAt(0) === '#') continue;
        Output.writeln(`${Output.bold(Input.PROMPT)}${command}`);
        const parser = new Parser(command.toString());
        const tokens = parser.tokenize();
        const ret = Command.runSync(tokens);
        Vars.setRet(ret);
        Output.writeRet();
        Output.writeln();
      }
    } catch (error) {
      if (error instanceof Error) {
        Output.writeln(`ERROR: ${error.message}`);
        Output.debug(`${error.stack}`);
      } else {
        Output.writeln(`ERROR: Unknown error`);
      }
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Output.writeln(Output.yellow('-'.repeat(80)));
      Input.prompt();
    }
  }

  protected formatAddress(): string {
    if (this.address === null) return 'unassigned';

    const p = this.address.toPointer();
    return Format.toHexString(p);
  }

  protected formatHits(): string {
    if (this.hits < 0) {
      return 'unlimited';
    } else if (this.hits === 0) {
      return 'disabled';
    } else {
      return this.hits.toString();
    }
  }

  protected abstract formatLength(): string;

  public toString(): string {
    const idxString = Output.green(`#${this.index.toString()}.`.padEnd(4, ' '));
    const typeString = `[${this.type.toString()}]`;
    const literalString = Output.yellow(this.literal);
    const addString = `@ $pc=${Output.blue(this.formatAddress())}`;
    const hitsString = `[hits:${this.formatHits()}]`;
    const lengthString = this.formatLength();
    const conditionalString = Output.blue(
      this.conditions.length === 0 ? 'unconditional' : 'conditional',
    );
    const header = [
      idxString,
      typeString,
      literalString,
      addString,
      hitsString,
      lengthString,
      conditionalString,
    ].join(' ');

    const lines = [header];

    if (this.conditions.length !== 0) {
      lines.push(Output.green('Conditions:'));
      this.conditions.forEach(c => {
        lines.push(`  - ${Output.yellow(c)}`);
      });
    }

    if (this.commands.length !== 0) {
      lines.push(Output.green('Commands:'));
      this.commands.forEach(c => {
        lines.push(`  - ${Output.yellow(c)}`);
      });
    }

    return `${lines.join('\n')}\n`;
  }

  abstract enable(): void;
  abstract disable(): void;
}
