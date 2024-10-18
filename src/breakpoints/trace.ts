import { Input } from '../io/input.js';
import { Output } from '../io/output.js';
import { Regs } from './regs.js';
import { Format } from '../misc/format.js';
import { BlockTrace } from '../traces/block.js';
import { Trace, TraceData, Traces } from '../traces/trace.js';
import { Var } from '../vars/var.js';
import { CallTrace } from '../traces/call.js';
import { CoverageTrace } from '../traces/coverage/trace.js';
import { BpType } from './bp.js';
import { BpCode } from './code.js';

export abstract class BpTrace extends BpCode {
  public readonly supports_commands: boolean = false;
  public depth: number;
  protected trace: Trace | null = null;

  protected constructor(
    index: number,
    address: Var | null,
    hits: number | null,
    depth: number,
  ) {
    super(index, address, hits);
    this.depth = depth;
  }

  protected override enableCode(addr: Var): void {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bp = this;
    this.listener = Interceptor.attach(addr.toPointer(), {
      onEnter() {
        if (bp.hits === 0) return;
        bp.break(this.threadId, this.context, this.returnAddress);
      },
      onLeave(_retVal) {
        bp.stopTrace(this.threadId, this.context);
      },
    });
  }

  protected override stopped(threadId: ThreadId, ctx: CpuContext) {
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.writeln(
      [
        `${Output.yellow('|')} Start Trace`,
        Output.green(`#${this.index}`),
        `[${this.type}]`,
        Output.yellow(this.literal),
        `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
        `$tid=${threadId}, depth=${this.depth}`,
      ].join(' '),
    );
    Output.writeln(Output.yellow('-'.repeat(80)));
    this.trace = this.startTrace(threadId);
  }
  protected abstract startTrace(threadId: ThreadId): Trace;

  protected stopTrace(threadId: ThreadId, ctx: CpuContext) {
    if (this.trace === null) return;
    try {
      this.trace.stop();

      Output.clearLine();
      Output.writeln(Output.yellow('-'.repeat(80)));
      Output.writeln(
        [
          `${Output.yellow('|')} Stop Trace`,
          Output.green(`#${this.index}`),
          `[${this.type}]`,
          Output.yellow(this.literal),
          `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
          `$tid=${threadId}, depth=${this.depth}`,
        ].join(' '),
      );
      Output.writeln(Output.yellow('-'.repeat(80)));

      const data = this.trace.data();
      setTimeout(() => this.displayTraceData(data));

      Traces.delete(threadId);
      this.trace = null;
    } finally {
      Input.prompt();
      Regs.clear();
    }
  }

  protected displayTraceData(trace: TraceData) {
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.writeln(`${Output.yellow('|')} Displaying trace:`);
    Output.writeln(Output.yellow('-'.repeat(80)));
    Input.suppressIntercept(true);
    Output.setIndent(true);
    Output.writeln();
    try {
      trace
        .lines()
        .slice(0, TraceData.MAX_LINES)
        .forEach(l => {
          Output.writeln(l);
        });
      Output.writeln();
    } finally {
      Output.setIndent(false);
      Input.suppressIntercept(false);
      Output.writeln(Output.yellow('-'.repeat(80)));
      Input.prompt();
    }
  }
}

export class BpBlockTrace extends BpTrace {
  public type: BpType = BpType.BlockTrace;

  public constructor(
    index: number,
    address: Var | null,
    hits: number | null,
    depth: number,
  ) {
    super(index, address, hits, depth);
  }

  protected override startTrace(threadId: ThreadId): Trace {
    return BlockTrace.create(threadId, this.depth, false);
  }
}

export class BpCallTrace extends BpTrace {
  public type: BpType = BpType.CallTrace;

  public constructor(
    index: number,
    address: Var | null,
    hits: number | null,
    depth: number,
  ) {
    super(index, address, hits, depth);
  }

  protected override startTrace(threadId: ThreadId): Trace {
    return CallTrace.create(threadId, this.depth);
  }
}

export class BpUniqueBlockTrace extends BpTrace {
  public type: BpType = BpType.UniqueBlockTrace;

  public constructor(
    index: number,
    address: Var | null,
    hits: number | null,
    depth: number,
  ) {
    super(index, address, hits, depth);
  }

  protected override startTrace(threadId: ThreadId): Trace {
    return BlockTrace.create(threadId, this.depth, true);
  }
}

export class BpCoverage extends BpTrace {
  public type: BpType = BpType.Coverage;

  public constructor(
    index: number,
    address: Var | null,
    hits: number | null,
    depth: number,
  ) {
    super(index, address, hits, depth);
  }

  protected override startTrace(threadId: ThreadId): Trace {
    return CoverageTrace.create(threadId, null, null);
  }
}
