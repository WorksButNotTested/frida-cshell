import { Format } from '../misc/format.js';
import { Output } from '../io/output.js';

export interface TraceData {
  display(): void;
}

export interface Trace {
  stop(): void;
  data(): TraceData;
}

export class Traces {
  private static readonly MAX_OFFSET: number = 1024;
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

  private static getAddressStringWithModuleOffset(address: NativePointer): string | null {
      const module = Process.findModuleByAddress(address);
      if (module === null) {
        return null;
      }

      const offset = address.sub(module.base);
      const prefix = `${module.name}+0x${offset.toString(16)}`;
      return `${Output.green(prefix.padEnd(40, '.'))} ${Output.yellow(Format.toHexString(address))}`;
  }

  public static getAddressString(address: NativePointer): string | null {
    const debug = DebugSymbol.fromAddress(address);
    if (debug === null || debug.name === null) {
      return this.getAddressStringWithModuleOffset(address);
    }
    const offset = debug.address.sub(DebugSymbol.fromName(debug.name).address);
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
}
