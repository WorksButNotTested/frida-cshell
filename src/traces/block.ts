import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { TraceBase, TraceData, TraceElement, Traces } from './trace.js';

class BlockTraceData extends TraceData {
  private trace: ArrayBuffer = new ArrayBuffer(0);
  private depth: number;

  public constructor(depth: number) {
    super();
    this.depth = depth;
  }

  public append(events: ArrayBuffer) {
    const newBuffer = new Uint8Array(this.trace.byteLength + events.byteLength);
    newBuffer.set(new Uint8Array(this.trace), 0);
    newBuffer.set(new Uint8Array(events), this.trace.byteLength);
    this.trace = newBuffer.buffer as ArrayBuffer;
  }

  public lines(): string[] {
    Output.debug(Output.yellow('parsing...'));
    const events = Stalker.parse(this.trace, {
      annotate: true,
      stringify: false,
    }) as StalkerEventFull[];

    Output.debug(Output.yellow('filtering events...'));
    const filtered = this.filterEvents(events, (e: StalkerEventFull) => {
      if (e.length !== 3) return null;
      const [kind, start, _end] = e;
      if (kind !== 'block' && kind !== 'compile') return null;
      return start as NativePointer;
    });

    Output.debug(Output.yellow('calculating depths...'));
    /* Assign a depth to each event */
    const depths: {
      depth: number;
      events: TraceElement[];
    } = filtered.reduce<{
      depth: number;
      events: TraceElement[];
    }>(
      (acc, event) => {
        switch (event.length) {
          case 3: {
            const [kind, start, _end] = event;
            const startPtr = start as NativePointer;
            switch (kind) {
              case 'block':
              case 'compile': {
                acc.events.push({ addr: startPtr, depth: acc.depth });
                break;
              }
            }
            break;
          }
          case 4: {
            const [kind, _from, _to, _depth] = event;
            switch (kind) {
              case 'call': {
                acc.depth += 1;
                break;
              }
              case 'ret': {
                acc.depth -= 1;
                break;
              }
            }
            break;
          }
        }
        return acc;
      },
      { depth: 0, events: [] },
    );

    Output.debug(Output.yellow('filtering depths...'));
    const elements = this.filterElements(depths.events, this.depth);
    Output.debug(Output.yellow('finding symbols...'));
    const named = this.nameElements(elements);
    Output.debug(Output.yellow('formatting...'));
    const strings = this.elementsToStrings(named);
    return strings;
  }

  public details(): string {
    return [
      'depth:',
      Output.blue(this.depth.toString()),
      'size:',
      Output.blue(Format.toSize(this.trace.byteLength)),
    ].join(' ');
  }
}

export class BlockTrace extends TraceBase<BlockTraceData> {
  private constructor(threadId: ThreadId, depth: number, unique: boolean) {
    const trace = new BlockTraceData(depth);
    super(threadId, trace);
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
    unique: boolean,
  ): BlockTrace {
    if (Traces.has(threadId)) {
      throw new Error(`trace already exists for threadId: ${threadId}`);
    }

    const trace = new BlockTrace(threadId, depth, unique);
    Traces.set(threadId, trace);
    return trace;
  }

  protected doStop() {
    Stalker.unfollow(this.threadId);
    Stalker.flush();
  }
}
