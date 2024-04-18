import { Var } from './var.js';

const THREAD_ID_NAME: string = 'tid';
const RETURN_ADDRESS_NAME: string = 'ra';
const ADDR_NAME: string = 'addr';
const PC_NAME: string = 'pc';
const RETVAL_NAME: string = 'ret';

export class Regs {
  private static threadId: ThreadId | undefined = undefined;
  private static ctx: CpuContext | undefined = undefined;
  private static returnAddress: NativePointer | undefined = undefined;
  private static addr: NativePointer | undefined = undefined;
  private static pc: NativePointer | undefined = undefined;
  private static retVal: InvocationReturnValue | undefined = undefined;

  private constructor() {}

  public static setThreadId(threadId: ThreadId) {
    this.threadId = threadId;
  }

  public static setContext(ctx: CpuContext) {
    this.ctx = ctx;
  }

  public static getContext(): CpuContext | undefined {
    return this.ctx;
  }

  public static setReturnAddress(returnAddress: NativePointer) {
    this.returnAddress = returnAddress;
  }

  public static setAddress(addr: NativePointer) {
    this.addr = addr;
  }

  public static setPc(pc: NativePointer) {
    this.pc = pc;
  }

  public static setRetVal(retVal: InvocationReturnValue) {
    this.retVal = retVal;
  }

  public static clear() {
    this.threadId = undefined;
    this.ctx = undefined;
    this.returnAddress = undefined;
    this.addr = undefined;
    this.pc = undefined;
    this.retVal = this.retVal;
  }

  private static isClear() {
    if (this.threadId !== undefined) return false;

    if (this.ctx !== undefined) return false;

    if (this.returnAddress !== undefined) return false;

    if (this.addr !== undefined) return false;

    if (this.pc !== undefined) return false;

    if (this.retVal !== undefined) return false;

    return true;
  }

  public static set(name: string, value: Var) {
    if (name === THREAD_ID_NAME) {
      throw new Error('Thread ID cannot be set');
    } else if (name === RETURN_ADDRESS_NAME) {
      throw new Error('Return address cannot be set');
    } else if (name === ADDR_NAME) {
      throw new Error('Addr cannot be set');
    } else if (name === RETVAL_NAME) {
      if (this.retVal === undefined)
        throw new Error(
          'Return Value not available outside of a function exit breakpoint',
        );
      const ptr = value.toPointer();
      this.retVal.replace(ptr);
    } else if (this.ctx === undefined) {
      if (name === PC_NAME) {
        throw new Error('Pc cannot be set');
      } else {
        throw new Error('Registers not available outside of a breakpoint');
      }
    } else {
      const regs = this.getRegs(this.ctx);
      if (!regs.has(name))
        throw new Error(`Register name '${name}' is invalid`);
      regs.set(name, value);
      this.setRegs(this.ctx, regs);
    }
  }

  public static get(name: string): Var {
    if (name === THREAD_ID_NAME) {
      if (this.threadId === undefined)
        throw new Error('Thread ID not available outside of a breakpoint');
      return new Var(uint64(this.threadId));
    } else if (name === RETURN_ADDRESS_NAME) {
      if (this.returnAddress === undefined)
        throw new Error('Return address not available outside of a breakpoint');
      return new Var(uint64(this.returnAddress.toString()));
    } else if (name === ADDR_NAME) {
      if (this.addr === undefined)
        throw new Error('Addr not available outside of a breakpoint');
      return new Var(uint64(this.addr.toString()));
    } else if (name === RETVAL_NAME) {
      if (this.retVal === undefined)
        throw new Error(
          'Return Value not available outside of a function exit breakpoint',
        );
      return new Var(uint64(this.retVal.toString()));
    } else if (this.ctx === undefined) {
      if (name === PC_NAME) {
        if (this.pc === undefined) {
          throw new Error('Pc not available outside of a breakpoint');
        }
        return new Var(uint64(this.pc.toString()));
      } else {
        throw new Error('Registers not available outside of a breakpoint');
      }
    } else {
      const regs = this.getRegs(this.ctx);
      const val = regs.get(name);
      if (val === undefined)
        throw new Error(`Variable name '${name}' is invalid`);
      return val;
    }
  }

  public static all(): [string, Var][] {
    const result: [string, Var][] = [];

    if (this.isClear())
      throw new Error('Registers not available outside of a breakpoint');

    if (this.ctx === undefined) {
      if (this.pc !== undefined) {
        result.push([PC_NAME, new Var(uint64(this.pc.toString()))]);
      }
    } else {
      const regs = Array.from(this.getRegs(this.ctx).entries());
      regs.forEach(r => result.push(r));
    }

    if (this.threadId !== undefined) {
      result.push([THREAD_ID_NAME, new Var(uint64(this.threadId))]);
    }

    if (this.returnAddress !== undefined) {
      result.push([
        RETURN_ADDRESS_NAME,
        new Var(uint64(this.returnAddress.toString())),
      ]);
    }

    if (this.addr !== undefined) {
      result.push([ADDR_NAME, new Var(uint64(this.addr.toString()))]);
    }

    if (this.retVal !== undefined) {
      result.push([RETVAL_NAME, new Var(uint64(this.retVal.toString()))]);
    }

    return result;
  }

  public static getRegs(cpuContext: CpuContext): Map<string, Var> {
    switch (Process.arch) {
      case 'ia32': {
        const ctx = cpuContext as Ia32CpuContext;
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
        const ctx = cpuContext as X64CpuContext;
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
        const ctx = cpuContext as ArmCpuContext;
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
        const ctx = cpuContext as Arm64CpuContext;
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

  public static setRegs(cpuContext: CpuContext, regs: Map<string, Var>) {
    switch (Process.arch) {
      case 'ia32': {
        const ctx = cpuContext as Ia32CpuContext;
        ctx.eax = regs.get('eax')?.toPointer() as NativePointer;
        ctx.ecx = regs.get('ecx')?.toPointer() as NativePointer;
        ctx.edx = regs.get('edx')?.toPointer() as NativePointer;
        ctx.ebx = regs.get('ebx')?.toPointer() as NativePointer;
        ctx.esp = regs.get('esp')?.toPointer() as NativePointer;
        ctx.ebp = regs.get('ebp')?.toPointer() as NativePointer;
        ctx.esi = regs.get('esi')?.toPointer() as NativePointer;
        ctx.edi = regs.get('edi')?.toPointer() as NativePointer;
        ctx.eip = regs.get('eip')?.toPointer() as NativePointer;
        break;
      }
      case 'x64': {
        const ctx = cpuContext as X64CpuContext;
        ctx.rax = regs.get('rax')?.toPointer() as NativePointer;
        ctx.rcx = regs.get('rcx')?.toPointer() as NativePointer;
        ctx.rdx = regs.get('rdx')?.toPointer() as NativePointer;
        ctx.rbx = regs.get('rbx')?.toPointer() as NativePointer;
        ctx.rsp = regs.get('rsp')?.toPointer() as NativePointer;
        ctx.rbp = regs.get('rbp')?.toPointer() as NativePointer;
        ctx.rsi = regs.get('rsi')?.toPointer() as NativePointer;
        ctx.rdi = regs.get('rdi')?.toPointer() as NativePointer;
        ctx.r8 = regs.get('r8')?.toPointer() as NativePointer;
        ctx.r9 = regs.get('r9')?.toPointer() as NativePointer;
        ctx.r10 = regs.get('r10')?.toPointer() as NativePointer;
        ctx.r11 = regs.get('r11')?.toPointer() as NativePointer;
        ctx.r12 = regs.get('r12')?.toPointer() as NativePointer;
        ctx.r13 = regs.get('r13')?.toPointer() as NativePointer;
        ctx.r14 = regs.get('r14')?.toPointer() as NativePointer;
        ctx.r15 = regs.get('r15')?.toPointer() as NativePointer;
        ctx.rip = regs.get('rip')?.toPointer() as NativePointer;
        break;
      }
      case 'arm': {
        const ctx = cpuContext as ArmCpuContext;
        ctx.cpsr = regs.get('cpsr')?.toU64().toNumber() as number;
        ctx.r0 = regs.get('r0')?.toPointer() as NativePointer;
        ctx.r1 = regs.get('r1')?.toPointer() as NativePointer;
        ctx.r2 = regs.get('r2')?.toPointer() as NativePointer;
        ctx.r3 = regs.get('r3')?.toPointer() as NativePointer;
        ctx.r4 = regs.get('r4')?.toPointer() as NativePointer;
        ctx.r5 = regs.get('r5')?.toPointer() as NativePointer;
        ctx.r6 = regs.get('r6')?.toPointer() as NativePointer;
        ctx.r7 = regs.get('r7')?.toPointer() as NativePointer;
        ctx.r8 = regs.get('r8')?.toPointer() as NativePointer;
        ctx.r9 = regs.get('r9')?.toPointer() as NativePointer;
        ctx.r10 = regs.get('r10')?.toPointer() as NativePointer;
        ctx.r11 = regs.get('r11')?.toPointer() as NativePointer;
        ctx.r12 = regs.get('r12')?.toPointer() as NativePointer;
        ctx.lr = regs.get('lr')?.toPointer() as NativePointer;
        ctx.pc = regs.get('pc')?.toPointer() as NativePointer;
        ctx.sp = regs.get('sp')?.toPointer() as NativePointer;
        break;
      }
      case 'arm64': {
        const ctx = cpuContext as Arm64CpuContext;
        ctx.nzcv = regs.get('nzcv')?.toU64().toNumber() as number;
        ctx.x0 = regs.get('x0')?.toPointer() as NativePointer;
        ctx.x1 = regs.get('x1')?.toPointer() as NativePointer;
        ctx.x2 = regs.get('x2')?.toPointer() as NativePointer;
        ctx.x3 = regs.get('x3')?.toPointer() as NativePointer;
        ctx.x4 = regs.get('x4')?.toPointer() as NativePointer;
        ctx.x5 = regs.get('x5')?.toPointer() as NativePointer;
        ctx.x6 = regs.get('x6')?.toPointer() as NativePointer;
        ctx.x7 = regs.get('x7')?.toPointer() as NativePointer;
        ctx.x8 = regs.get('x8')?.toPointer() as NativePointer;
        ctx.x9 = regs.get('x9')?.toPointer() as NativePointer;
        ctx.x10 = regs.get('x10')?.toPointer() as NativePointer;
        ctx.x11 = regs.get('x11')?.toPointer() as NativePointer;
        ctx.x12 = regs.get('x12')?.toPointer() as NativePointer;
        ctx.x13 = regs.get('x13')?.toPointer() as NativePointer;
        ctx.x14 = regs.get('x14')?.toPointer() as NativePointer;
        ctx.x15 = regs.get('x15')?.toPointer() as NativePointer;
        ctx.x16 = regs.get('x16')?.toPointer() as NativePointer;
        ctx.x17 = regs.get('x17')?.toPointer() as NativePointer;
        ctx.x18 = regs.get('x18')?.toPointer() as NativePointer;
        ctx.x19 = regs.get('x19')?.toPointer() as NativePointer;
        ctx.x20 = regs.get('x20')?.toPointer() as NativePointer;
        ctx.x21 = regs.get('x21')?.toPointer() as NativePointer;
        ctx.x22 = regs.get('x22')?.toPointer() as NativePointer;
        ctx.x23 = regs.get('x23')?.toPointer() as NativePointer;
        ctx.x24 = regs.get('x24')?.toPointer() as NativePointer;
        ctx.x25 = regs.get('x25')?.toPointer() as NativePointer;
        ctx.x26 = regs.get('x26')?.toPointer() as NativePointer;
        ctx.x27 = regs.get('x27')?.toPointer() as NativePointer;
        ctx.x28 = regs.get('x28')?.toPointer() as NativePointer;
        ctx.fp = regs.get('fp')?.toPointer() as NativePointer;
        ctx.lr = regs.get('lr')?.toPointer() as NativePointer;
        ctx.pc = regs.get('pc')?.toPointer() as NativePointer;
        ctx.sp = regs.get('sp')?.toPointer() as NativePointer;
        break;
      }
      case 'mips':
      default:
        throw new Error(`Unknown or unsupported architecture: ${Process.arch}`);
    }
  }
}
