import { Output } from '../io/output.js';
import { Trace, TraceData, Traces } from './trace.js';

class CallTraceData implements TraceData {
  private static readonly MAX_CALLS = 1024;
  private trace: ArrayBuffer = new ArrayBuffer(0);
  private depth: number;

  public constructor(depth: number) {
    this.depth = depth;
  }

  public append(events: ArrayBuffer) {
    const newBuffer = new Uint8Array(this.trace.byteLength + events.byteLength);
    newBuffer.set(new Uint8Array(this.trace), 0);
    newBuffer.set(new Uint8Array(events), this.trace.byteLength);
    this.trace = newBuffer.buffer as ArrayBuffer;
  }

  public display() {
    const events = Stalker.parse(this.trace, {
      annotate: true,
      stringify: false,
    }) as StalkerEventFull[];

    let numOutput = 0;
    let currentDepth = 0;
    let first = true;
    for (const e of events) {
      const [kind, from, to, _depth] = e;
      if (kind === 'call') {
        currentDepth += 1;
        if (!first && currentDepth >= this.depth) continue;
        const toName = Traces.getAddressString(to as NativePointer);
        if (toName === null) continue;

        if (first) {
          const idx = `${numOutput.toString().padStart(4, ' ')}. `;
          const fromName = Traces.getAddressString(from as NativePointer);
          if (fromName === null) continue;
          Output.writeln(`${Output.bold(idx)}${fromName}`);
          currentDepth = 1;
          first = false;
        }
        if (numOutput >= CallTraceData.MAX_CALLS) {
          Output.writeln(Output.red(`TRACE TRUNCATED`));
          return;
        }
        numOutput += 1;
        const idx = `${numOutput.toString().padStart(4, ' ')}. `;
        const depth = currentDepth > 0 ? '\t'.repeat(currentDepth) : '';
        Output.writeln(`${depth}${Output.bold(idx)}${toName}`);
      } else if (kind === 'ret') {
        if (currentDepth > 0) {
          currentDepth -= 1;
        }
      }
    }
  }
}

export class CallTrace implements Trace {
  private threadId: ThreadId;
  private trace: CallTraceData;

  private constructor(threadId: ThreadId, depth: number) {
    this.threadId = threadId;
    this.trace = new CallTraceData(depth);
    Stalker.follow(threadId, {
      events: {
        call: true,
        ret: true,
      },
      onReceive: (events: ArrayBuffer) => {
        if (this.trace !== null) {
          this.trace.append(events);
        }
      },
    });
  }

  public static create(threadId: ThreadId, depth: number): CallTrace {
    if (Traces.has(threadId)) {
      throw new Error(`trace already exists for threadId: ${threadId}`);
    }

    const trace = new CallTrace(threadId, depth);
    Traces.set(threadId, trace);
    return trace;
  }

  public stop() {
    Stalker.unfollow(this.threadId);
    Stalker.flush();
  }

  public data(): CallTraceData {
    return this.trace;
  }
}
