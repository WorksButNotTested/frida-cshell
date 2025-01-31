import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { TraceBase, TraceData, TraceElement, Traces } from './trace.js';

class CallTraceData extends TraceData {
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
    /* Filter events for which we have no module information */
    const filtered = this.filterEvents(events, (e: StalkerEventFull) => {
      if (e.length !== 4) return null;
      const [kind, _from, to, _depth] = e;
      if (kind !== 'call') return null;
      return to as NativePointer;
    });

    Output.debug(Output.yellow('calculating depths...'));
    /* Assign a depth to each event */
    const depths: {
      first: boolean;
      depth: number;
      events: TraceElement[];
    } = filtered.reduce<{
      first: boolean;
      depth: number;
      events: TraceElement[];
    }>(
      (acc, event) => {
        if (event.length !== 4) return acc;
        const [kind, from, to, _depth] = event;
        const [fromPtr, toPtr] = [from as NativePointer, to as NativePointer];
        switch (kind) {
          case 'call': {
            if (acc.first) {
              acc.events.push({ addr: fromPtr, depth: acc.depth });
              acc.first = false;
            }
            acc.depth += 1;
            acc.events.push({ addr: toPtr, depth: acc.depth });
            break;
          }
          case 'ret': {
            acc.depth -= 1;
            break;
          }
        }
        return acc;
      },
      { first: true, depth: 0, events: [] },
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

export class CallTrace extends TraceBase<CallTraceData> {
  private constructor(threadId: ThreadId, depth: number) {
    const trace = new CallTraceData(depth);
    super([threadId], trace);
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

  protected doStop() {
    const threadId = this.threadIds[0] as number;
    Stalker.unfollow(threadId);
    Stalker.flush();
  }
}
