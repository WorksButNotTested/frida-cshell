import { Format } from '../misc/format.js';
import { Output } from '../io/output.js';

export type TraceElement = { addr: NativePointer; depth: number };
export type NamedElement = { name: string; depth: number };

export abstract class TraceData {
  private static readonly MAX_OFFSET: number = 1024;

  public abstract append(events: ArrayBuffer): void;
  public abstract lines(): string[];
  public abstract details(): string;

  protected filterEvents(
    events: StalkerEventFull[],
    addr: (e: StalkerEventFull) => NativePointer | null,
  ): StalkerEventFull[] {
    const modules = this.getModules();
    return events.filter(e => {
      const address = addr(e);
      if (address === null) return true;
      return this.isAddressInModule(address, modules);
    });
  }

  private getModules(): Module[] {
    return Process.enumerateModules().sort((a, b) => a.base.compare(b.base));
  }

  private isAddressInModule(value: NativePointer, ranges: Module[]): boolean {
    let left = 0;
    let right = ranges.length - 1;

    while (left <= right) {
      const mid = Math.floor((left + right) / 2);
      const range = ranges[mid] as Module;

      if (value >= range.base && value <= range.base.add(range.size)) {
        return true;
      } else if (value < range.base) {
        right = mid - 1;
      } else {
        left = mid + 1;
      }
    }

    return false;
  }

  protected filterElements(
    elements: TraceElement[],
    depth: number,
  ): TraceElement[] {
    /* Get the smallest depth value from depths */
    const smallest = elements.reduce<number>((acc, event) => {
      if (event.depth < acc) {
        return event.depth;
      } else {
        return acc;
      }
    }, 0);

    /* Adjust all the depths relative to the smallest, and filter by the maximum depth */
    const adjusted = elements
      .map(e => {
        return { addr: e.addr, depth: e.depth - smallest };
      })
      .filter(e => e.depth <= depth);

    return adjusted;
  }

  protected nameElements(elements: TraceElement[]): NamedElement[] {
    const symbolCache: { [key: string]: DebugSymbol | null } = {};
    const stringCache: { [key: string]: string | null } = {};

    /* Lookup the names for all of the addresses */
    const named = elements
      .map(e => {
        const k = e.addr.toString();
        let v = stringCache[k];

        if (v === undefined) {
          v = TraceData.getAddressString(e.addr, symbolCache);
          stringCache[k] = v;
        }

        return {
          depth: e.depth,
          name: v,
        };
      })
      .filter(e => e.name !== null) as NamedElement[];
    return named;
  }

  private static getDebugSymbol(
    key: NativePointer | string,
    cache: { [key: string]: DebugSymbol | null },
  ): DebugSymbol | null {
    if (typeof key === 'string') {
      let v = cache[key];
      if (v === undefined) {
        v = DebugSymbol.fromName(key);
        cache[key] = v;
      }
      return v;
    } else {
      const k = key.toString();
      let v = cache[k];
      if (v === undefined) {
        v = DebugSymbol.fromAddress(key);
        cache[k] = v;
      }
      return v;
    }
  }

  private static getAddressStringWithModuleOffset(
    address: NativePointer,
  ): string | null {
    const module = Process.findModuleByAddress(address);
    if (module === null) {
      return null;
    }

    const offset = address.sub(module.base);
    const prefix = `${module.name}+0x${offset.toString(16)}`;
    return `${Output.green(prefix.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(address))}`;
  }

  private static getAddressString(
    address: NativePointer,
    cache: { [key: string]: DebugSymbol | null },
  ): string | null {
    const debug = this.getDebugSymbol(address, cache);
    if (debug === null || debug.name === null) {
      return this.getAddressStringWithModuleOffset(address);
    }

    const namedSymbol = this.getDebugSymbol(debug.name, cache);
    if (namedSymbol === null) {
      return this.getAddressStringWithModuleOffset(address);
    }

    const offset = debug.address.sub(namedSymbol.address);
    if (offset.compare(this.MAX_OFFSET) > 0) {
      return this.getAddressStringWithModuleOffset(address);
    }

    const prefix = debug.moduleName === null ? '' : `${debug.moduleName}!`;
    const name = `${prefix}${debug.name}+0x${offset.toString(16)}`;
    const symbol = `${Output.green(name.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(debug.address))}`;

    if (debug.fileName !== null && debug.lineNumber !== null) {
      if (debug.fileName.length !== 0 && debug.lineNumber !== 0) {
        return `${symbol} ${Output.blue(debug.fileName)}:${Output.blue(debug.lineNumber.toString())}`;
      }
    }
    return symbol;
  }

  protected elementsToStrings(elements: NamedElement[]): string[] {
    return elements.map((e, i) => {
      const idx = `${i.toString().padStart(4, ' ')}. `;
      const depth = e.depth > 0 ? ' '.repeat(e.depth * 2) : '';
      return `${depth}${Output.bold(idx)}${e.name}`;
    });
  }
}

export interface Trace {
  stop(): void;
  data(): TraceData;
  thread(): ThreadId;
  isStopped(): boolean;
}

export abstract class TraceBase<D extends TraceData> implements Trace {
  protected threadId: ThreadId;
  protected trace: D;
  private stopped: boolean = false;

  protected constructor(threadId: ThreadId, trace: D) {
    this.threadId = threadId;
    this.trace = trace;
  }

  public stop() {
    if (this.stopped) return;
    this.doStop();
    this.stopped = true;
  }

  protected abstract doStop(): void;

  public data(): D {
    return this.trace;
  }

  public thread(): ThreadId {
    return this.threadId;
  }

  public isStopped(): boolean {
    return this.stopped;
  }
}

export class Traces {
  private static byThreadId: Map<ThreadId, Trace> = new Map<ThreadId, Trace>();

  public static has(threadId: ThreadId): boolean {
    return this.byThreadId.has(threadId);
  }

  public static get(threadId: ThreadId): Trace | null {
    return this.byThreadId.get(threadId) ?? null;
  }

  public static set(threadId: ThreadId, trace: Trace) {
    this.byThreadId.set(threadId, trace);
  }

  public static delete(threadId: ThreadId) {
    const trace = this.byThreadId.get(threadId);
    if (trace === undefined) return;
    trace.stop();
    this.byThreadId.delete(threadId);
  }
}
