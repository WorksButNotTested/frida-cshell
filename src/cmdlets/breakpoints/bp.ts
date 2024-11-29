import { Bp, BpType } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import { CmdLetBase } from '../../commands/cmdlet.js';
import { Input, InputInterceptLine } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Var } from '../../vars/var.js';

enum InputMode {
  Conditions = 'conditions',
  Commands = 'commands',
}

export abstract class TypedBpCmdLet
  extends CmdLetBase
  implements InputInterceptLine
{
  protected static readonly CONDITIONAL_CHAR: string = '?';
  public abstract readonly bpType: BpType;
  protected abstract runCreate(tokens: Token[]): Var | null;
  protected abstract runModify(tokens: Token[]): Var | null;
  protected abstract usageCreate(): string;
  protected abstract usageModify(): string;

  private last: Bp | null = null;
  private mode: InputMode = InputMode.Conditions;
  private conditions: string[] | null = [];
  private commands: string[] | null = [];

  category = 'breakpoints';

  public runSync(tokens: Token[]): Var {
    const retModify = this.runModify(tokens);
    if (retModify !== null) return retModify;

    const retCreate = this.runCreate(tokens);
    if (retCreate !== null) return retCreate;

    const retShow = this.runShow(tokens);
    if (retShow !== null) return retShow;

    const retDelete = this.runDelete(tokens);
    if (retDelete !== null) return retDelete;

    return this.usage();
  }

  private runDelete(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseIndex, this.parseDelete]);
    if (vars === null) return null;
    const [index, _] = vars as [number, string];

    const bp = Bps.delete(this.bpType, index);
    Output.writeln(`Deleted ${bp.toString()}`);
    return bp.address ?? Var.ZERO;
  }

  private runShow(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseIndex]);
    if (vars === null) return null;
    const [_, [index]] = vars as [[], [number | null]];

    if (index === null) {
      Output.writeln(
        `${Output.blue(this.bpType)} ${Output.blue('breakpoints')}:`,
      );
      Bps.all()
        .filter(bp => bp.type === this.bpType)
        .forEach(bp => Output.writeln(bp.toString(), true));
      return Var.ZERO;
    } else {
      const bp = Bps.get(this.bpType, index);
      if (bp === null) throw new Error(`breakpoint #${index} not found`);

      Output.writeln(bp.toString());
      return bp.address;
    }
  }

  public usage(): Var {
    const show = this.usageShow();
    const create = this.usageCreate();
    const modify = this.usageModify();
    const usage: string = `Usage: ${this.name}
${Output.bold('show:')}
${show}

${Output.bold('create:')}
${create}

${Output.bold('modify:')}
${modify}

${Output.bold('delete:')}

${this.name} ${CmdLetBase.NUM_CHAR}n # - delete a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to delete

${Output.bold('NOTE:')} Set hits to '*' for unlimited breakpoint.`;

    Output.writeln(usage);
    return Var.ZERO;
  }

  protected usageShow(): string {
    const usage: string = `    
${this.name} - show all ${this.bpType} breakpoints

${this.name} ${CmdLetBase.NUM_CHAR}n - show a ${this.bpType} breakpoint
   ${CmdLetBase.NUM_CHAR}n      the number of the breakpoint to show`;
    return usage;
  }

  protected parseConditional(token: Token): string | null {
    const literal = token.getLiteral();
    if (literal !== TypedBpCmdLet.CONDITIONAL_CHAR) return null;
    return literal;
  }

  protected editBreakpoint(bp: Bp, conditional: boolean) {
    this.last = bp;
    if (conditional) {
      this.mode = InputMode.Conditions;
      if (bp.conditions.length > 0) {
        Output.writeln(Output.bold("Breakpoint's current conditions:"));
        bp.conditions.forEach(c => Output.writeln(`  - ${Output.yellow(c)}`));
      } else {
        Output.writeln(Output.bold('Breakpoint currently has no conditions'));
      }
      Output.writeln(Output.green("Enter breakpoint's conditions:"));
      Input.setInterceptLine(this);
      return;
    } else {
      bp.conditions = [];
    }

    if (bp.supports_commands) {
      this.mode = InputMode.Commands;
      if (bp.commands.length > 0) {
        Output.writeln(Output.bold("Breakpoint's current commands:"));
        bp.commands.forEach(c => Output.writeln(`  - ${Output.yellow(c)}`));
      } else {
        Output.writeln(Output.bold('Breakpoint currently has no commands'));
      }
      Output.writeln(Output.green("Enter breakpoint's commands:"));
      Input.setInterceptLine(this);
    } else {
      bp.commands = [];
      bp.enable();
    }
  }

  startLines(): void {
    switch (this.mode) {
      case InputMode.Conditions:
        this.conditions = [];
        break;
      case InputMode.Commands:
        this.commands = [];
        break;
    }
  }

  addLine(line: string): void {
    switch (this.mode) {
      case InputMode.Conditions:
        if (this.conditions === null) return;
        this.conditions.push(line);
        break;
      case InputMode.Commands:
        if (this.commands === null) return;
        this.commands.push(line);
        break;
    }
  }

  done(): void {
    Output.writeln();
    if (this.last === null) return;

    switch (this.mode) {
      case InputMode.Conditions:
        if (this.conditions) {
          this.last.conditions = this.conditions;
        }

        if (this.last.supports_commands) {
          if (this.last.commands.length > 0) {
            Output.writeln(Output.bold("Breakpoint's current commands:"));
            this.last.commands.forEach(c =>
              Output.writeln(`  - ${Output.yellow(c)}`),
            );
          } else {
            Output.writeln(Output.bold('Breakpoint currently has no commands'));
          }
          Output.writeln(Output.green("Enter breakpoint's commands:"));
          this.mode = InputMode.Commands;
          Input.setInterceptLine(this);
        } else {
          this.last.commands = [];
          this.last.enable();
        }
        break;
      case InputMode.Commands:
        if (this.commands) {
          this.last.commands = this.commands;
        }
        this.last.enable();
        break;
    }
  }

  clearLines(): void {
    switch (this.mode) {
      case InputMode.Conditions:
        this.conditions = [];
        break;
      case InputMode.Commands:
        this.commands = [];
        break;
    }
    this.done();
  }

  saveLines(): void {
    this.done();
  }

  cancelLines(): void {
    switch (this.mode) {
      case InputMode.Conditions:
        this.conditions = null;
        break;
      case InputMode.Commands:
        this.commands = null;
        break;
    }
    this.done();
  }
}
