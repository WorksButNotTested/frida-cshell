import { Output } from '../io/output.js';
import { Mem } from '../memory/mem.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';
import { Bp, BpKind, BpType } from './bp.js';
import { Regs } from './regs.js';

class MemoryCallbacks implements MemoryAccessCallbacks {
  onAccess = function (details: MemoryAccessDetails) {
    const idx = details.rangeIndex;
    const bps = BpMemory.getAllActive();

    if (idx >= bps.length)
      throw new Error(`failed to find memory breakpoint idx: ${idx}`);

    const bp = bps[idx] as BpMemory;
    bp.break(details);
    BpMemory.refresh();
  };
}

export abstract class BpMemory extends Bp {
  private static callbacks = new MemoryCallbacks();
  private static memoryBps: Map<string, BpMemory> = new Map<string, BpMemory>();

  public static register(bp: BpMemory) {
    const key = this.buildKey(bp.type, bp.index);
    this.memoryBps.set(key, bp);
    this.refresh();
  }

  private static buildKey(type: BpType, index: number): string {
    return `${type}:${index.toString()}`;
  }

  public static unregister(bp: BpMemory) {
    const key = this.buildKey(bp.type, bp.index);
    this.memoryBps.delete(key);
    this.refresh();
  }

  public static refresh() {
    this.disableAll();
    this.enableAll();
  }

  public static disableAll() {
    MemoryAccessMonitor.disable();
  }

  public static enableAll() {
    const ranges = Array.from(this.memoryBps.values())
      .map(bp => bp.getRange())
      .filter(r => r !== null) as MemoryAccessRange[];

    if (ranges.length === 0) return;
    MemoryAccessMonitor.enable(ranges, this.callbacks);
  }

  public static getAllActive(): BpMemory[] {
    const bps = Array.from(this.memoryBps.values());
    return bps.filter(bp => bp.getRange() !== null);
  }

  public static addressHasBreakpoint(address: NativePointer): boolean {
    const ranges = Array.from(this.memoryBps.values())
      .map(bp => bp.getRange())
      .filter(r => r !== null) as MemoryAccessRange[];
    const aligned = Mem.pageAlignDown(address);

    return ranges.some(range => {
      if (range.base.add(range.size).compare(aligned) <= 0) return false;
      if (range.base.compare(aligned.add(Process.pageSize)) >= 0) return false;
      return true;
    });
  }

  public kind: BpKind = BpKind.Memory;
  public readonly supports_commands: boolean = true;

  enable(): void {
    BpMemory.register(this);
  }

  disable(): void {
    BpMemory.unregister(this);
  }

  public break(details: MemoryAccessDetails) {
    if (!this.checkOperation(details.operation)) return;

    if (this.hits === 0) return;

    Regs.setAddress(details.address);
    Regs.setPc(details.from);
    Regs.setBreakpointId(this.index);

    try {
      if (this.runConditions()) {
        if (this.hits > 0) this.hits--;

        Output.clearLine();
        Output.writeln(Output.yellow('-'.repeat(80)));
        Output.writeln(
          [
            `${Output.yellow('|')} Break`,
            Output.green(`#${this.index}`),
            `[${this.type}]`,
            Output.yellow(this.literal),
            `@ $pc=${Output.blue(Format.toHexString(details.from))}`,
            `$addr=${Output.blue(Format.toHexString(details.address))}`,
          ].join(' '),
        );
        Output.writeln(Output.yellow('-'.repeat(80)));
        this.runCommands();
      }
    } finally {
      Regs.clear();
    }
  }

  protected abstract checkOperation(operation: MemoryOperation): boolean;

  protected formatLength(): string {
    return `[length:${this.length}]`;
  }

  public getRange(): MemoryAccessRange | null {
    if (this.address === null) return null;
    if (this.length === 0) return null;
    if (this.hits === 0) return null;
    return {
      base: this.address.toPointer() as NativePointer,
      size: this.length,
    };
  }
}

export class BpReadMemory extends BpMemory {
  public type: BpType = BpType.MemoryRead;

  public constructor(
    index: number,
    address: Var | null,
    length: number | null,
    hits: number | null,
  ) {
    super(index, address, length, hits);
  }

  protected checkOperation(operation: MemoryOperation): boolean {
    return operation === 'read';
  }
}

export class BpWriteMemory extends BpMemory {
  public type: BpType = BpType.MemoryWrite;

  public constructor(
    index: number,
    address: Var | null,
    length: number | null,
    hits: number | null,
  ) {
    super(index, address, length, hits);
  }

  protected checkOperation(operation: MemoryOperation): boolean {
    return operation === 'write';
  }
}
