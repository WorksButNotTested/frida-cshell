import { Bp, BpKind, BpType } from '../breakpoints/bp.js';
import { Bps } from '../breakpoints/bps.js';
import { CmdLet, CmdLetEdit } from '../commands/cmdlet.js';
import { Input } from '../io/input.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const DELETE_CHAR: string = '#';
const NUM_CHAR: string = '#';
const UNLIMITED_CHAR: string = '*';

abstract class TypedBpCmdLet extends CmdLet implements CmdLetEdit {
  public abstract readonly bpType: BpType;

  category = 'breakpoints';

  public usage(): Var {
    const kind = Bp.getBpKind(this.bpType);
    const lenStr: string = kind == BpKind.Memory ? ' len ' : '';
    const lenDesc: string =
      kind == BpKind.Memory
        ? 'len     the length of the memory region to watch\n'
        : '';
    const INSN_BP_USAGE: string = `Usage: ${this.name}
${Output.bold('show:')}

${this.name} - show all ${this.bpType} breakpoints

${this.name} ${NUM_CHAR}n - show a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to show


${Output.bold('create:')}

${this.name} hits - create ${this.bpType} breakpoint without assigning an address
   hits    the number of times the breakpoint should fire

${this.name} hits addr ${lenStr} - create ${this.bpType} breakpoint
   hits    the number of times the breakpoint should fire
   addr    the address to create the breakpoint
   ${lenDesc}
${Output.bold('modify:')}

${this.name} ${NUM_CHAR}n hits - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire

${this.name} ${NUM_CHAR}n hits addr ${lenStr} - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire
   addr    the address to move the breakpoint
   ${lenDesc}
${Output.bold('delete:')}

${this.name} ${NUM_CHAR}n # - delete a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to delete

${Output.bold('NOTE:')} Set hits to '*' for unlimited breakpoint.
`;
    Output.write(INSN_BP_USAGE);
    return Var.ZERO;
  }

  private parseIndex(token: Token | undefined): number | undefined {
    if (token === undefined) return undefined;

    const literal = token.getLiteral();
    if (literal === undefined) return undefined;

    if (!literal.startsWith(NUM_CHAR)) return undefined;

    const numStr = literal.slice(1);
    const val = parseInt(numStr);
    return val;
  }

  private parseDelete(token: Token | undefined): boolean {
    if (token === undefined) return false;

    const literal = token.getLiteral();
    if (literal === undefined) return false;

    if (literal !== DELETE_CHAR) return false;

    return true;
  }

  private parseHits(token: Token | undefined): number | undefined {
    if (token === undefined) return undefined;

    if (token.getLiteral() === UNLIMITED_CHAR) return -1;

    const hits = token?.toVar()?.toU64().toNumber();
    return hits;
  }

  private parseLength(token: Token | undefined): number | undefined {
    if (Bp.getBpKind(this.bpType) == BpKind.Code) return 0;
    return token?.toVar()?.toU64().toNumber();
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length !== 0) return undefined;

    Output.writeln(
      `${Output.blue(this.bpType)} ${Output.blue('breakpoints')}:`,
    );
    Bps.all()
      .filter(bp => bp.type === this.bpType)
      .forEach(bp => Output.writeln(bp.toString(true)));
    return Var.ZERO;
  }

  private runWithHits(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const hits = this.parseHits(tokens[0]);
    if (hits === undefined) return undefined;

    const bp = Bps.create(this.bpType, hits);
    Output.writeln(`Created ${bp.toString()}`);
    Input.setEdit(this);

    return Var.ZERO;
  }

  private runWithHitsAndAddr(tokens: Token[]): Var | undefined {
    if (Bp.getBpKind(this.bpType) == BpKind.Code) {
      if (tokens.length != 2) return undefined;
    } else {
      if (tokens.length != 3) return undefined;
    }

    const hits = this.parseHits(tokens[0]);
    if (hits === undefined) return undefined;

    const literal = tokens[1]?.getLiteral();
    if (literal === undefined) return undefined;

    const addr = tokens[1]?.toVar();
    if (addr === undefined) return undefined;

    const length = this.parseLength(tokens[2]);
    if (length === undefined) return undefined;

    const bp = Bps.create(this.bpType, hits, addr, literal, length);
    Output.writeln(`Created ${bp.toString()}`);
    Input.setEdit(this);

    return addr;
  }

  private runWithIndex(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const index = this.parseIndex(tokens[0]);
    if (index === undefined) return undefined;

    const bp = Bps.get(this.bpType, index);
    if (bp === undefined) throw new Error(`Breakpoint #${index} not found`);

    Output.writeln(bp.toString());
    return bp.address ?? Var.ZERO;
  }

  private runWithIndexAndHash(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const index = this.parseIndex(tokens[0]);
    if (index === undefined) return undefined;

    const hash = this.parseDelete(tokens[1]);
    if (!hash) return undefined;

    const bp = Bps.delete(this.bpType, index);
    Output.writeln(`Deleted ${bp.toString()}`);
    return bp.address ?? Var.ZERO;
  }

  private runWithIndexAndHits(tokens: Token[]): Var | undefined {
    if (tokens.length != 2) return undefined;

    const index = this.parseIndex(tokens[0]);
    if (index === undefined) return undefined;

    const hits = this.parseHits(tokens[1]);
    if (hits === undefined) return undefined;

    const bp = Bps.modify(this.bpType, index, hits);
    Output.writeln(`Modified ${bp.toString()}`);
    Input.setEdit(this);

    return Var.ZERO;
  }

  private runWithIndexHitsAndAddr(tokens: Token[]): Var | undefined {
    if (Bp.getBpKind(this.bpType) == BpKind.Code) {
      if (tokens.length != 3) return undefined;
    } else {
      if (tokens.length != 4) return undefined;
    }

    const index = this.parseIndex(tokens[0]);
    if (index === undefined) return undefined;

    const hits = this.parseHits(tokens[1]);
    if (hits === undefined) return undefined;

    const literal = tokens[2]?.getLiteral();
    if (literal === undefined) return undefined;

    const addr = tokens[2]?.toVar();
    if (addr === undefined) return undefined;

    const length = this.parseLength(tokens[3]);
    if (length === undefined) return length;

    const bp = Bps.modify(this.bpType, index, hits, addr, literal, length);
    Output.writeln(`Modified ${bp.toString()}`);
    Input.setEdit(this);

    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithIndexHitsAndAddress = this.runWithIndexHitsAndAddr(tokens);
    if (retWithIndexHitsAndAddress !== undefined)
      return retWithIndexHitsAndAddress;

    const retWithIndexAndHits = this.runWithIndexAndHits(tokens);
    if (retWithIndexAndHits !== undefined) return retWithIndexAndHits;

    const retWithIndexAndHash = this.runWithIndexAndHash(tokens);
    if (retWithIndexAndHash !== undefined) return retWithIndexAndHash;

    const retWithIndex = this.runWithIndex(tokens);
    if (retWithIndex !== undefined) return retWithIndex;

    const retWithHitsAndAddr = this.runWithHitsAndAddr(tokens);
    if (retWithHitsAndAddr !== undefined) return retWithHitsAndAddr;

    const retWithHits = this.runWithHits(tokens);
    if (retWithHits !== undefined) return retWithHits;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }

  addCommandLine(line: string) {
    Bps.addCommandLine(line);
  }

  done() {
    Bps.done();
  }

  abort() {
    Bps.abort();
  }
}

export class InsnBpCmdLet extends TypedBpCmdLet {
  name = '@i';
  bpType = BpType.Instruction;
  help = `${this.bpType} breakpoint`;
}

export class FunctionEntryBpCmdLet extends TypedBpCmdLet {
  name = '@f';
  bpType = BpType.FunctionEntry;
  help = `${this.bpType} breakpoint`;
}

export class FunctionExitBpCmdLet extends TypedBpCmdLet {
  name = '@F';
  bpType = BpType.FunctionExit;
  help = `${this.bpType} breakpoint`;
}

export class ReadBpCmdLet extends TypedBpCmdLet {
  name = '@r';
  bpType = BpType.MemoryRead;
  help = `${this.bpType} breakpoint`;
}

export class WriteBpCmdLet extends TypedBpCmdLet {
  name = '@w';
  bpType = BpType.MemoryWrite;
  help = `${this.bpType} breakpoint`;
}
