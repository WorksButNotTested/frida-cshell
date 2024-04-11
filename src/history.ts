import { Line } from './line.js';
import { Command } from './command.js';
import { Output } from './output.js';
import { Parser } from './parser.js';
import { CmdLets } from './cmdlets.js';
import { Token } from './token.js';
import { Var } from './var.js';

export class History {
  private static readonly MAX_HISTORY: number = 100;

  private static line: Line = new Line();
  private static history: string[] = [];
  private static index: number = -1;

  private constructor() {}

  public static getCurrent(): Line {
    return History.line;
  }

  private static isHistoryCommand(token: Token | undefined): boolean {
    if (token === undefined) return false;

    const cmdlet = CmdLets.getByName(token.getLiteral());
    if (cmdlet === undefined) return false;

    if (cmdlet.name !== 'h') return false;

    return true;
  }

  public static run(): Var {
    /* If our command is not empty */
    if (this.line.getLength() == 0 && this.line.peek(1) === ' ') {
      return Var.ZERO;
    }

    const parser = new Parser(this.line.toString());
    const tokens = parser.tokenize();
    const isHistoryCommand = this.isHistoryCommand(tokens[0]);

    /* If our command isn't already top-most */
    if (this.line.toString() != this.history[0] && !isHistoryCommand) {
      this.history.unshift(this.line.toString());
      if (this.history.length >= this.MAX_HISTORY) this.history.pop();
    }

    Output.writeln();
    const ret = Command.run(tokens);
    return ret;
  }

  public static clearLine() {
    this.index = -1;
    this.line = new Line();
  }

  public static rerun(idx: number): Var {
    const str = this.history[idx];
    if (str === undefined) throw new Error(`Invalid history index: ${idx}`);
    this.line = new Line(str);
    Output.prompt();
    return this.run();
  }

  public static up() {
    if (this.index >= this.history.length - 1) return;
    this.index++;
    this.line = new Line(this.history[this.index]);
  }

  public static down() {
    if (this.index == -1) return;
    this.index--;
    this.line = new Line(this.history[this.index]);
  }

  public static all(): string[] {
    return this.history;
  }
}
