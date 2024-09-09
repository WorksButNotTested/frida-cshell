import { BP_LENGTH, Bp, BpKind, BpType } from '../breakpoints/bp.js';
import { Bps } from '../breakpoints/bps.js';
import { CmdLet } from '../commands/cmdlet.js';
import { Input, InputInterceptLine } from '../io/input.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

const DELETE_CHAR: string = '#';
const NUM_CHAR: string = '#';
const UNLIMITED_CHAR: string = '*';

abstract class TypedBpCmdLet extends CmdLet implements InputInterceptLine {
  public abstract readonly bpType: BpType;

  category = 'breakpoints';

  public runSync(tokens: Token[]): Var {
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

  private runWithIndexHitsAndAddr(tokens: Token[]): Var | null {
    switch (this.bpType) {
      case BpType.Instruction:
      case BpType.FunctionEntry:
      case BpType.FunctionExit: {
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

        const bp = Bps.modify(
          this.bpType,
          index,
          hits,
          addr,
          literal,
          BP_LENGTH,
        );
        Output.writeln(`Modified ${bp.toString()}`);
        this.addCommands();
        return addr;
      }
      case BpType.FunctionTrace:
      case BpType.MemoryRead:
      case BpType.MemoryWrite: {
        if (tokens.length !== 4) return null;

        const [a0, a1, a2, a3] = tokens;
        const [t0, t1, t2, t3] = [
          a0 as Token,
          a1 as Token,
          a2 as Token,
          a3 as Token,
        ];
        const [addr, extra] = [t2.toVar(), t3.toVar()];

        if (addr === null) return null;
        if (extra === null) return null;

        const index = this.parseIndex(t0);
        if (index === null) return null;

        const hits = this.parseHits(t1);
        if (hits === null) return null;

        const literal = t2.getLiteral();

        if (this.bpType == BpType.FunctionTrace) {
          const bp = Bps.modify(
            this.bpType,
            index,
            hits,
            addr,
            literal,
            BP_LENGTH,
            extra.toU64().toNumber(),
          );
          Output.writeln(`Modified ${bp.toString()}`);
        } else {
          const bp = Bps.modify(
            this.bpType,
            index,
            hits,
            addr,
            literal,
            extra.toU64().toNumber(),
          );
          Output.writeln(`Modified ${bp.toString()}`);
        }
        this.addCommands();
        return addr;
      }
    }
  }

  private addCommands() {
    switch (this.bpType) {
      case BpType.Instruction:
      case BpType.FunctionEntry:
      case BpType.FunctionExit:
      case BpType.MemoryRead:
      case BpType.MemoryWrite:
        Input.setInterceptLine(this);
        break;
      case BpType.FunctionTrace:
        this.done();
        break;
    }
  }

  private parseIndex(token: Token): number | null {
    const literal = token.getLiteral();
    if (!literal.startsWith(NUM_CHAR)) return null;

    const numStr = literal.slice(1);
    const val = parseInt(numStr);

    if (isNaN(val)) return null;
    return val;
  }

  private parseHits(token: Token): number | null {
    if (token.getLiteral() === UNLIMITED_CHAR) return -1;

    const v = token.toVar();
    if (v === null) return null;

    const hits = v.toU64().toNumber();
    return hits;
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
    this.addCommands();

    return Var.ZERO;
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

  private parseDelete(token: Token): boolean {
    const literal = token.getLiteral();
    if (literal !== DELETE_CHAR) return false;

    return true;
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

  private runWithHitsAndAddr(tokens: Token[]): Var | null {
    switch (this.bpType) {
      case BpType.Instruction:
      case BpType.FunctionEntry:
      case BpType.FunctionExit: {
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

        this.addCommands();

        return addr;
      }
      case BpType.FunctionTrace:
      case BpType.MemoryRead:
      case BpType.MemoryWrite: {
        if (tokens.length !== 3) return null;
        const [a0, a1, a2] = tokens;
        const [t0, t1, t2] = [a0 as Token, a1 as Token, a2 as Token];
        const [addr, extra] = [t1.toVar(), t2.toVar()];

        if (addr === null) return null;
        if (extra === null) return null;

        const hits = this.parseHits(t0);
        if (hits === null) return null;

        const literal = t1.getLiteral();

        if (this.bpType == BpType.FunctionTrace) {
          const bp = Bps.create(
            this.bpType,
            hits,
            addr,
            literal,
            BP_LENGTH,
            extra.toU64().toNumber(),
          );
          Output.writeln(`Created ${bp.toString()}`);
        } else {
          const bp = Bps.create(
            this.bpType,
            hits,
            addr,
            literal,
            extra.toU64().toNumber(),
          );
          Output.writeln(`Created ${bp.toString()}`);
        }

        this.addCommands();

        return addr;
      }
    }
  }

  private runWithHits(tokens: Token[]): Var | null {
    if (tokens.length !== 1) return null;

    const t0 = tokens[0] as Token;

    const hits = this.parseHits(t0);
    if (hits === null) return null;

    const bp = Bps.create(this.bpType, hits);
    Output.writeln(`Created ${bp.toString()}`);
    this.addCommands();

    return Var.ZERO;
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

  public usage(): Var {
    const kind = Bp.getBpKind(this.bpType);
    const lenStr: string = kind === BpKind.Memory ? ' len ' : '';

    let extraDesc = '';
    switch (this.bpType) {
      case BpType.Instruction:
      case BpType.FunctionEntry:
      case BpType.FunctionExit:
        break;
      case BpType.FunctionTrace:
        extraDesc = 'depth   the maximum depth of callstack to follow\n';
        break;
      case BpType.MemoryRead:
      case BpType.MemoryWrite:
        extraDesc = 'len     the length of the memory region to watch\n';
        break;
    }
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
   ${extraDesc}
${Output.bold('modify:')}

${this.name} ${NUM_CHAR}n hits - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire

${this.name} ${NUM_CHAR}n hits addr ${lenStr} - modify a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to modify
   hits    the number of times the breakpoint should fire
   addr    the address to move the breakpoint
   ${extraDesc}
${Output.bold('delete:')}

${this.name} ${NUM_CHAR}n # - delete a ${this.bpType} breakpoint
   ${NUM_CHAR}n      the number of the breakpoint to delete

${Output.bold('NOTE:')} Set hits to '*' for unlimited breakpoint.
`;
    Output.write(INSN_BP_USAGE);
    return Var.ZERO;
  }

  addLine(line: string) {
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

export class FunctionTraceBpCmdLet extends TypedBpCmdLet {
  name = '@t';
  bpType = BpType.FunctionTrace;
  help = `${this.bpType} breakpoint`;
}
