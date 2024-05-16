import { Line } from './line.js';
import { Command } from '../commands/command.js';
import { Output } from '../io/output.js';
import { Parser } from '../io/parser.js';
import { CmdLets } from '../commands/cmdlets.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';
import { Input } from '../io/input.js';

export class History {
  private static readonly MAX_HISTORY: number = 100;

  private static line: Line = new Line();
  private static history: string[] = [];
  private static index: number = -1;

  private constructor() {}

  public static getCurrent(): Line {
    return History.line;
  }

  public static rerun(idx: number): Var {
    if (idx >= this.history.length)
      throw new Error(`invalid history index: ${idx}`);
    const str = this.history[idx] as string;
    this.line = new Line(str);
    Input.prompt();
    return this.run();
  }

  public static run(): Var {
    const parser = new Parser(this.line.toString());
    const tokens = parser.tokenize();

    if (tokens.length !== 0) {
      const t0 = tokens[0] as Token;
      const isHistoryCommand = this.isHistoryCommand(t0);

      /* If our command isn't already top-most */
      if (this.line.toString() !== this.history[0] && !isHistoryCommand) {
        this.history.unshift(this.line.toString());
        if (this.history.length >= this.MAX_HISTORY) this.history.pop();
      }
    }

    Output.writeln();
    const ret = Command.run(tokens);
    return ret;
  }

  private static isHistoryCommand(token: Token): boolean {
    const cmdlet = CmdLets.getByName(token.getLiteral());
    if (cmdlet === null) return false;

    if (cmdlet.name !== 'h') return false;

    return true;
  }

  public static up() {
    if (this.index >= this.history.length - 1) return;
    this.index++;
    this.line = new Line(this.history[this.index]);
  }

  public static down() {
    if (this.index === -1) return;
    this.index--;
    this.line = new Line(this.history[this.index]);
  }

  public static clearLine() {
    this.index = -1;
    this.line = new Line();
  }

  public static all(): string[] {
    return this.history;
  }
}
