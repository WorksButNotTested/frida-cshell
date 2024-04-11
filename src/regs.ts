import { Var } from './var.js';

export class Regs {
  private static threadId: ThreadId | undefined = undefined;
  private static ctx: CpuContext | undefined = undefined;

  private constructor() {}

  public static setThreadId(threadId: ThreadId) {
    this.threadId = threadId;
  }

  public static setContext(ctx: CpuContext) {
    this.ctx = ctx;
  }

  public static clear() {
    this.threadId = undefined;
    this.ctx = undefined;
  }

  public static set(name: string, value: Var) {
    const regs = this.getRegs();
    if (!regs.has(name)) throw new Error(`Variable name '${name}' is invalid`);
    regs.set(name, value);
    this.setRegs(regs);
  }

  public static get(name: string): Var {
    const regs = this.getRegs();
    const val = regs.get(name);
    if (val === undefined)
      throw new Error(`Variable name '${name}' is invalid`);

    return val;
  }

  public static all(): [string, Var][] {
    if (this.ctx == undefined)
      throw new Error('Registers not available outside of a breakpoint');

    return Array.from(this.getRegs().entries());
  }

  public static getThreadId(): ThreadId {
    if (this.threadId == undefined)
      throw new Error('Thread ID not available outside of a breakpoint');
    return this.threadId;
  }

  private static getRegs(): Map<string, Var> {
    if (this.ctx === undefined)
      throw new Error('Registers not available outside of a breakpoint');
    switch (Process.arch) {
      case 'ia32': {
        const ctx = this.ctx as Ia32CpuContext;
        return new Map([
          ['eax', new Var(uint64(ctx.eax.toString()))],
          ['ecx', new Var(uint64(ctx.ecx.toString()))],
          ['edx', new Var(uint64(ctx.edx.toString()))],
          ['ebx', new Var(uint64(ctx.ebx.toString()))],
          ['esp', new Var(uint64(ctx.esp.toString()))],
          ['ebp', new Var(uint64(ctx.ebp.toString()))],
          ['esi', new Var(uint64(ctx.esi.toString()))],
          ['edi', new Var(uint64(ctx.edi.toString()))],
          ['eip', new Var(uint64(ctx.eip.toString()))],
        ]);
      }
      case 'x64': {
        const ctx = this.ctx as X64CpuContext;
        return new Map([
          ['rax', new Var(uint64(ctx.rax.toString()))],
          ['rcx', new Var(uint64(ctx.rcx.toString()))],
          ['rdx', new Var(uint64(ctx.rdx.toString()))],
          ['rbx', new Var(uint64(ctx.rbx.toString()))],
          ['rsp', new Var(uint64(ctx.rsp.toString()))],
          ['rbp', new Var(uint64(ctx.rbp.toString()))],
          ['rsi', new Var(uint64(ctx.rsi.toString()))],
          ['rdi', new Var(uint64(ctx.rdi.toString()))],
          ['r8', new Var(uint64(ctx.r8.toString()))],
          ['r9', new Var(uint64(ctx.r9.toString()))],
          ['r10', new Var(uint64(ctx.r10.toString()))],
          ['r11', new Var(uint64(ctx.r11.toString()))],
          ['r12', new Var(uint64(ctx.r12.toString()))],
          ['r13', new Var(uint64(ctx.r13.toString()))],
          ['r14', new Var(uint64(ctx.r14.toString()))],
          ['r15', new Var(uint64(ctx.r15.toString()))],
          ['rip', new Var(uint64(ctx.rip.toString()))],
        ]);
      }
      case 'arm': {
        const ctx = this.ctx as ArmCpuContext;
        return new Map([
          ['cpsr', new Var(uint64(ctx.cpsr.toString()))],
          ['r0', new Var(uint64(ctx.r0.toString()))],
          ['r1', new Var(uint64(ctx.r1.toString()))],
          ['r2', new Var(uint64(ctx.r2.toString()))],
          ['r3', new Var(uint64(ctx.r3.toString()))],
          ['r4', new Var(uint64(ctx.r4.toString()))],
          ['r5', new Var(uint64(ctx.r5.toString()))],
          ['r6', new Var(uint64(ctx.r6.toString()))],
          ['r7', new Var(uint64(ctx.r7.toString()))],
          ['r8', new Var(uint64(ctx.r8.toString()))],
          ['r9', new Var(uint64(ctx.r9.toString()))],
          ['r10', new Var(uint64(ctx.r10.toString()))],
          ['r11', new Var(uint64(ctx.r11.toString()))],
          ['r12', new Var(uint64(ctx.r12.toString()))],
          ['lr', new Var(uint64(ctx.lr.toString()))],
          ['pc', new Var(uint64(ctx.pc.toString()))],
          ['sp', new Var(uint64(ctx.sp.toString()))],
        ]);
      }
      case 'arm64': {
        const ctx = this.ctx as Arm64CpuContext;
        return new Map([
          ['nzcv', new Var(uint64(ctx.nzcv.toString()))],
          ['x0', new Var(uint64(ctx.x0.toString()))],
          ['x1', new Var(uint64(ctx.x1.toString()))],
          ['x2', new Var(uint64(ctx.x2.toString()))],
          ['x3', new Var(uint64(ctx.x3.toString()))],
          ['x4', new Var(uint64(ctx.x4.toString()))],
          ['x5', new Var(uint64(ctx.x5.toString()))],
          ['x6', new Var(uint64(ctx.x6.toString()))],
          ['x7', new Var(uint64(ctx.x7.toString()))],
          ['x8', new Var(uint64(ctx.x8.toString()))],
          ['x9', new Var(uint64(ctx.x9.toString()))],
          ['x10', new Var(uint64(ctx.x10.toString()))],
          ['x11', new Var(uint64(ctx.x11.toString()))],
          ['x12', new Var(uint64(ctx.x12.toString()))],
          ['x13', new Var(uint64(ctx.x13.toString()))],
          ['x14', new Var(uint64(ctx.x14.toString()))],
          ['x15', new Var(uint64(ctx.x15.toString()))],
          ['x16', new Var(uint64(ctx.x16.toString()))],
          ['x17', new Var(uint64(ctx.x17.toString()))],
          ['x18', new Var(uint64(ctx.x18.toString()))],
          ['x19', new Var(uint64(ctx.x19.toString()))],
          ['x20', new Var(uint64(ctx.x20.toString()))],
          ['x21', new Var(uint64(ctx.x21.toString()))],
          ['x22', new Var(uint64(ctx.x22.toString()))],
          ['x23', new Var(uint64(ctx.x23.toString()))],
          ['x24', new Var(uint64(ctx.x24.toString()))],
          ['x25', new Var(uint64(ctx.x25.toString()))],
          ['x26', new Var(uint64(ctx.x26.toString()))],
          ['x27', new Var(uint64(ctx.x27.toString()))],
          ['x28', new Var(uint64(ctx.x28.toString()))],
          ['fp', new Var(uint64(ctx.fp.toString()))],
          ['lr', new Var(uint64(ctx.lr.toString()))],
          ['pc', new Var(uint64(ctx.pc.toString()))],
          ['sp', new Var(uint64(ctx.sp.toString()))],
        ]);
      }
      case 'mips':
      default:
        throw new Error(`Unknown or unsupported architecture: ${Process.arch}`);
        break;
    }
  }

  private static setRegs(regs: Map<string, Var>) {
    throw new Error('TODO');
  }
}
