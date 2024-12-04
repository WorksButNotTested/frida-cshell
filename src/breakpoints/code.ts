import { Output } from '../io/output.js';
import { Overlay } from '../memory/overlay.js';
import { Regs } from './regs.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';
import { Bp, BpKind, BpType } from './bp.js';
import { Tls } from '../tls/tls.js';

export abstract class BpCode extends Bp {
  public kind: BpKind = BpKind.Code;
  private static readonly BP_CODE_LENGTH: number = 16;

  protected listener: InvocationListener | null;
  private overlay: string | null = null;

  protected constructor(
    index: number,
    address: Var | null,
    hits: number | null,
  ) {
    super(index, address, BpCode.BP_CODE_LENGTH, hits);
    this.listener = null;
    this.overlay = null;
  }

  public enable() {
    if (this.address === null) return;
    if (this.listener !== null) return;
    this.overlay = Overlay.add(this.address.toPointer(), this.length);
    const addr = this.address;
    this.enableCode(addr);
  }

  protected abstract enableCode(addr: Var): void;

  public override disable(): void {
    if (this.listener === null) return;
    this.listener.detach();
    this.listener = null;
    Interceptor.flush();
    if (this.overlay === null) return;
    Overlay.remove(this.overlay);
  }

  protected break(
    threadId: ThreadId,
    ctx: CpuContext,
    returnAddress: NativePointer,
    retVal: InvocationReturnValue | null = null,
  ) {
    if (this.hits === 0) return;

    Regs.setThreadId(threadId);
    Regs.setContext(ctx);
    Regs.setReturnAddress(returnAddress);
    Regs.setBreakpointId(this.index);
    Regs.setTls(Tls.getTls());
    if (retVal !== null) Regs.setRetVal(retVal);

    try {
      if (this.runConditions()) {
        if (this.hits > 0) this.hits--;
        this.stopped(threadId, ctx);
        this.runCommands();
      }
    } finally {
      Regs.clear();
    }
  }

  protected stopped(threadId: ThreadId, ctx: CpuContext) {
    Output.clearLine();
    Output.writeln(Output.yellow('-'.repeat(80)));
    Output.writeln(
      [
        `${Output.yellow('|')} Break`,
        Output.green(`#${this.index}`),
        `[${this.type}]`,
        Output.yellow(this.literal),
        `@ $pc=${Output.blue(Format.toHexString(ctx.pc))}`,
        `$tid=${threadId}`,
      ].join(' '),
    );
    Output.writeln(Output.yellow('-'.repeat(80)));
  }

  protected formatLength(): string {
    return '';
  }
}

export class BpCodeInstruction extends BpCode {
  public type: BpType = BpType.Instruction;
  public readonly supports_commands: boolean = true;

  public constructor(index: number, address: Var | null, hits: number | null) {
    super(index, address, hits);
  }

  protected override enableCode(addr: Var): void {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bp = this;
    this.listener = Interceptor.attach(
      addr.toPointer(),
      function (this: InvocationContext, _args: InvocationArguments) {
        bp.break(this.threadId, this.context, this.returnAddress);
      },
    );
  }
}

export class BpFunctionEntry extends BpCode {
  public type: BpType = BpType.FunctionEntry;
  public readonly supports_commands: boolean = true;

  public constructor(index: number, address: Var | null, hits: number | null) {
    super(index, address, hits);
  }

  protected override enableCode(addr: Var): void {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bp = this;
    this.listener = Interceptor.attach(addr.toPointer(), {
      onEnter() {
        bp.break(this.threadId, this.context, this.returnAddress);
      },
    });
  }
}

export class BpFunctionExit extends BpCode {
  public type: BpType = BpType.FunctionExit;
  public readonly supports_commands: boolean = true;

  public constructor(index: number, address: Var | null, hits: number | null) {
    super(index, address, hits);
  }

  protected override enableCode(addr: Var): void {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const bp = this;
    this.listener = Interceptor.attach(addr.toPointer(), {
      onLeave(retVal) {
        bp.break(this.threadId, this.context, this.returnAddress, retVal);
      },
    });
  }
}
