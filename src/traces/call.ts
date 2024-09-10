import { Output } from '../io/output.js';
import { Trace, Traces } from './trace.js';

export class CallTrace implements Trace {
  private static readonly MAX_CALLS = 1024;
  private threadId: ThreadId;
  private trace: ArrayBuffer = new ArrayBuffer(0);
  private depth: number;

  private constructor(threadId: ThreadId, depth: number) {
    this.threadId = threadId;
    this.depth = depth;
    Stalker.follow(threadId, {
      events: {
        call: true,
        ret: true,
      },
      onReceive: (events: ArrayBuffer) => {
        const newBuffer = new Uint8Array(
          this.trace.byteLength + events.byteLength,
        );
        newBuffer.set(new Uint8Array(this.trace), 0);
        newBuffer.set(new Uint8Array(events), this.trace.byteLength);
        this.trace = newBuffer.buffer as ArrayBuffer;
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
        if (currentDepth >= this.depth) continue;
        const toName = Traces.getAddressString(to as NativePointer);
        if (toName === null) continue;

        if (first) {
          const fromName = Traces.getAddressString(from as NativePointer);
          if (fromName === null) continue;
          Output.writeln(fromName);
          currentDepth = 1;
          first = false;
        }
        if (numOutput >= CallTrace.MAX_CALLS) return;
        numOutput += 1;
        if (currentDepth > 0) {
          Output.write('\t'.repeat(currentDepth));
        }
        Output.writeln(toName);
      } else if (kind === 'ret') {
        if (currentDepth > 0) {
          currentDepth -= 1;
        }
      }
    }
  }

  public stop() {
    Stalker.unfollow(this.threadId);
    Stalker.flush();
  }
}
