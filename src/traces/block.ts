import { Output } from '../io/output.js';
import { Trace, TraceData, Traces } from './trace.js';

class BlockTraceData implements TraceData {
  private static readonly MAX_BLOCKS = 1024;
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
      switch (e.length) {
        case 3: {
          const [kind, start, _end] = e;
          if (!first && currentDepth >= this.depth) break;
          if (kind !== 'block' && kind !== 'compile') break;
          const name = Traces.getAddressString(start as NativePointer);
          if (name === null) break;
          if (first) {
            currentDepth = 0;
            first = false;
          }
          if (numOutput >= BlockTraceData.MAX_BLOCKS) {
            Output.writeln(Output.red(`TRACE TRUNCATED`));
            return;
          }
          numOutput += 1;
          const idx = `${numOutput.toString().padStart(4, ' ')}. `;
          const depth = currentDepth > 0 ? '\t'.repeat(currentDepth) : '';
          Output.writeln(`${depth}${Output.bold(idx)}${name}`);
          break;
        }
        case 4: {
          const [kind, _from, _to, _depth] = e;
          if (kind === 'call') {
            currentDepth += 1;
          } else if (kind === 'ret') {
            if (currentDepth > 0) {
              currentDepth -= 1;
            }
          }
          break;
        }
        default:
          break;
      }
    }
  }
}

export class BlockTrace implements Trace {
  private threadId: ThreadId;
  private trace: BlockTraceData;

  private constructor(threadId: ThreadId, depth: number, unique: boolean) {
    this.threadId = threadId;
    this.trace = new BlockTraceData(depth);
    Stalker.follow(threadId, {
      events: {
        call: true,
        ret: true,
        block: !unique,
        compile: unique,
      },
      onReceive: (events: ArrayBuffer) => {
        if (this.trace !== null) {
          this.trace.append(events);
        }
      },
    });
  }

  public static create(
    threadId: ThreadId,
    depth: number,
    unique: boolean = false,
  ): BlockTrace {
    if (Traces.has(threadId)) {
      throw new Error(`trace already exists for threadId: ${threadId}`);
    }

    const trace = new BlockTrace(threadId, depth, unique);
    Traces.set(threadId, trace);
    return trace;
  }

  public stop() {
    Stalker.unfollow(this.threadId);
    Stalker.flush();
  }

  public data(): BlockTraceData {
    return this.trace;
  }
}
