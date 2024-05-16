import { BP_LENGTH, Bp, BpKind, BpType } from '../breakpoints/bp.js';
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
    const lenStr: string = kind === BpKind.Memory ? ' len ' : '';
    const lenDesc: string =
      kind === BpKind.Memory
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

  private parseIndex(token: Token): number | null {
    const literal = token.getLiteral();
    if (!literal.startsWith(NUM_CHAR)) return null;

    const numStr = literal.slice(1);
    const val = parseInt(numStr);

    if (isNaN(val)) return null;
    return val;
  }

  private parseDelete(token: Token | undefined): boolean {
    if (token === undefined) return false;

    const literal = token.getLiteral();
    if (literal === undefined) return false;

    if (literal !== DELETE_CHAR) return false;

    return true;
  }

  private parseHits(token: Token): number | null {
    if (token.getLiteral() === UNLIMITED_CHAR) return -1;

    const v = token.toVar();
    if (v === null) return null;

    const hits = v.toU64().toNumber();
    return hits;
  }

  private runWithoutParams(tokens: Token[]): Var | null {
    if (tokens.length !== 0) return null;

    Output.writeln(
      `${Output.blue(this.bpType)} ${Output.blue('breakpoints')}:`,
    );
    Bps.all()
      .filter(bp => bp.type === this.bpType)
      .forEach(bp => Output.writeln(bp.toString(true)));
    return Var.ZERO;
  }

  private runWithHits(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;

    const hits = this.parseHits(t0);
    if (hits === null) return null;

    const bp = Bps.create(this.bpType, hits);
    Output.writeln(`Created ${bp.toString()}`);
    Input.setEdit(this);

    return Var.ZERO;
  }

  private runWithHitsAndAddr(tokens: Token[]): Var | null {
    if (Bp.getBpKind(this.bpType) === BpKind.Code) {
      if (tokens.length !== 2) return null;
      const [a0, a1] = tokens;
      const [t0, t1] = [a0 as Token, a1 as Token];

      const hits = this.parseHits(t0);
      if (hits === null) return null;

      const literal = t1.getLiteral();
      const addr = t1.toVar();
      if (addr === null) return null;

      const bp = Bps.create(this.bpType, hits, addr, literal, BP_LENGTH);
      Output.writeln(`Created ${bp.toString()}`);

      Input.setEdit(this);

      return addr;
    } else {
      if (tokens.length !== 3) return null;
      const [a0, a1, a2] = tokens;
      const [t0, t1, t2] = [a0 as Token, a1 as Token, a2 as Token];
      const [addr, length] = [t1.toVar(), t2.toVar()];

      if (addr === null) return null;
      if (length === null) return null;

      const hits = this.parseHits(t0);
      if (hits === null) return null;

      const literal = t1.getLiteral();

      const bp = Bps.create(
        this.bpType,
        hits,
        addr,
        literal,
        length.toU64().toNumber(),
      );
      Output.writeln(`Created ${bp.toString()}`);

      Input.setEdit(this);

      return addr;
    }
  }

  private runWithIndex(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;
    const index = this.parseIndex(t0);
    if (index === null) return null;

    const bp = Bps.get(this.bpType, index);
    if (bp === null) throw new Error(`breakpoint #${index} not found`);

    Output.writeln(bp.toString());
    return bp.address;
  }

  private runWithIndexAndHash(tokens: Token[]): Var | null {
    if (tokens.length !== 2) return null;

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];

    const index = this.parseIndex(t0);
    if (index === null) return null;

    const hash = this.parseDelete(t1);
    if (!hash) return null;

    const bp = Bps.delete(this.bpType, index);
    Output.writeln(`Deleted ${bp.toString()}`);
    return bp.address ?? Var.ZERO;
  }

  private runWithIndexAndHits(tokens: Token[]): Var | null {
    if (tokens.length !== 2) return null;

    const [a0, a1] = tokens;
    const [t0, t1] = [a0 as Token, a1 as Token];

    const index = this.parseIndex(t0);
    if (index === null) return null;

    const hits = this.parseHits(t1);
    if (hits === null) return null;

    const bp = Bps.modify(this.bpType, index, hits);
    Output.writeln(`Modified ${bp.toString()}`);
    Input.setEdit(this);

    return Var.ZERO;
  }

  private runWithIndexHitsAndAddr(tokens: Token[]): Var | null {
    if (Bp.getBpKind(this.bpType) === BpKind.Code) {
      if (tokens.length !== 3) return null;
      const [a0, a1, a2] = tokens;
      const [t0, t1, t2] = [a0 as Token, a1 as Token, a2 as Token];

      const index = this.parseIndex(t0);
      if (index === null) return null;

      const hits = this.parseHits(t1);
      if (hits === null) return null;

      const literal = t2.getLiteral();
      const addr = t2.toVar();
      if (addr === null) return null;

      const bp = Bps.modify(this.bpType, index, hits, addr, literal, BP_LENGTH);
      Output.writeln(`Modified ${bp.toString()}`);
    } else {
      if (tokens.length !== 4) return null;

      const [a0, a1, a2, a3] = tokens;
      const [t0, t1, t2, t3] = [
        a0 as Token,
        a1 as Token,
        a2 as Token,
        a3 as Token,
      ];
      const [addr, length] = [t2.toVar(), t3.toVar()];

      if (addr === null) return null;
      if (length === null) return null;

      const index = this.parseIndex(t0);
      if (index === null) return null;

      const hits = this.parseHits(t1);
      if (hits === null) return null;

      const literal = t2.getLiteral();
      const bp = Bps.modify(
        this.bpType,
        index,
        hits,
        addr,
        literal,
        length.toU64().toNumber(),
      );
      Output.writeln(`Modified ${bp.toString()}`);
    }

    Input.setEdit(this);
    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithIndexHitsAndAddress = this.runWithIndexHitsAndAddr(tokens);
    if (retWithIndexHitsAndAddress !== null) return retWithIndexHitsAndAddress;

    const retWithIndexAndHits = this.runWithIndexAndHits(tokens);
    if (retWithIndexAndHits !== null) return retWithIndexAndHits;

    const retWithIndexAndHash = this.runWithIndexAndHash(tokens);
    if (retWithIndexAndHash !== null) return retWithIndexAndHash;

    const retWithIndex = this.runWithIndex(tokens);
    if (retWithIndex !== null) return retWithIndex;

    const retWithHitsAndAddr = this.runWithHitsAndAddr(tokens);
    if (retWithHitsAndAddr !== null) return retWithHitsAndAddr;

    const retWithHits = this.runWithHits(tokens);
    if (retWithHits !== null) return retWithHits;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== null) return retWithoutParams;

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
