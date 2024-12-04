import { Var } from '../vars/var.js';

enum PseudoRegNames {
  TID = 'tid',
  RA = 'ra',
  ADDRESS = 'addr',
  BP = 'bp',
  TLS = 'tls',
}

type PseudoRegs = {
  [K in PseudoRegNames]: Var | null;
};

export class Regs {
  private static readonly PC_NAME: string = 'pc';
  private static readonly RETVAL_NAME = 'ret';
  private static ctx: CpuContext | null = null;
  private static pc: Var | null = null;
  private static retVal: InvocationReturnValue | null = null;

  private static pseudoRegs: PseudoRegs = {
    [PseudoRegNames.TID]: null,
    [PseudoRegNames.RA]: null,
    [PseudoRegNames.ADDRESS]: null,
    [PseudoRegNames.BP]: null,
    [PseudoRegNames.TLS]: null,
  };

  private constructor() {}

  public static setPc(pc: NativePointer) {
    this.pc = new Var(uint64(pc.toString()), Regs.PC_NAME);
  }

  public static setThreadId(threadId: ThreadId) {
    this.pseudoRegs[PseudoRegNames.TID] = new Var(
      uint64(threadId),
      PseudoRegNames.TID,
    );
  }

  public static setReturnAddress(returnAddress: NativePointer) {
    this.pseudoRegs[PseudoRegNames.RA] = new Var(
      uint64(returnAddress.toString()),
      PseudoRegNames.RA,
    );
  }

  public static setAddress(addr: NativePointer) {
    this.pseudoRegs[PseudoRegNames.ADDRESS] = new Var(
      uint64(addr.toString()),
      PseudoRegNames.ADDRESS,
    );
  }

  public static setRetVal(retVal: InvocationReturnValue) {
    this.retVal = retVal;
  }

  public static setBreakpointId(breakpointId: number) {
    this.pseudoRegs[PseudoRegNames.BP] = Var.fromId(breakpointId);
  }

  public static setTls(tls: NativePointer) {
    this.pseudoRegs[PseudoRegNames.TLS] = new Var(
      uint64(tls.toString()),
      PseudoRegNames.TLS,
    );
  }

  public static get(name: string): Var {
    if (name in this.pseudoRegs) {
      const key = name as PseudoRegNames;
      const v = this.pseudoRegs[key];
      if (v === null)
        throw new Error(`${name} not available outside of a breakpoint`);
      return v;
    } else if (name === Regs.RETVAL_NAME) {
      if (this.retVal === null)
        throw new Error(
          'return Value not available outside of a function exit breakpoint',
        );
      return new Var(uint64(this.retVal.toString()), Regs.RETVAL_NAME);
    } else if (this.ctx === null) {
      if (name === Regs.PC_NAME) {
        if (this.pc === null) {
          throw new Error('pc not available outside of a breakpoint');
        }
        return this.pc;
      } else {
        throw new Error('registers not available outside of a breakpoint');
      }
    } else {
      const regs = this.getRegs(this.ctx);
      if (!regs.has(name))
        throw new Error(`variable name '${name}' is invalid`);
      const val = regs.get(name) as Var;
      return val;
    }
  }

  public static set(name: string, value: Var) {
    if (name in this.pseudoRegs) {
      throw new Error(`${name} cannot be set`);
    } else if (name === Regs.RETVAL_NAME) {
      if (this.retVal === null)
        throw new Error(
          'return Value not available outside of a function exit breakpoint',
        );
      const ptr = value.toPointer();
      this.retVal.replace(ptr);
    } else if (this.ctx === null) {
      if (name === Regs.PC_NAME) {
        throw new Error('pc cannot be set');
      } else {
        throw new Error('registers not available outside of a breakpoint');
      }
    } else {
      const regs = this.getRegs(this.ctx);
      if (!regs.has(name))
        throw new Error(`register name '${name}' is invalid`);
      regs.set(name, value);
      this.setRegs(this.ctx, regs);
    }
  }

  public static getRegs(cpuContext: CpuContext): Map<string, Var> {
    switch (Process.arch) {
      case 'ia32': {
        const ctx = cpuContext as Ia32CpuContext;
        return new Map([
          ['eax', new Var(uint64(ctx.eax.toString()), 'eax')],
          ['ecx', new Var(uint64(ctx.ecx.toString()), 'ecx')],
          ['edx', new Var(uint64(ctx.edx.toString()), 'edx')],
          ['ebx', new Var(uint64(ctx.ebx.toString()), 'ebx')],
          ['esp', new Var(uint64(ctx.esp.toString()), 'esp')],
          ['ebp', new Var(uint64(ctx.ebp.toString()), 'ebp')],
          ['esi', new Var(uint64(ctx.esi.toString()), 'esi')],
          ['edi', new Var(uint64(ctx.edi.toString()), 'edi')],
          ['eip', new Var(uint64(ctx.eip.toString()), 'eip')],
          ['pc', new Var(uint64(ctx.pc.toString()), 'pc')],
          ['sp', new Var(uint64(ctx.sp.toString()), 'sp')],
        ]);
      }
      case 'x64': {
        const ctx = cpuContext as X64CpuContext;
        return new Map([
          ['rax', new Var(uint64(ctx.rax.toString()), 'rax')],
          ['rcx', new Var(uint64(ctx.rcx.toString()), 'rcx')],
          ['rdx', new Var(uint64(ctx.rdx.toString()), 'rdx')],
          ['rbx', new Var(uint64(ctx.rbx.toString()), 'rbx')],
          ['rsp', new Var(uint64(ctx.rsp.toString()), 'rsp')],
          ['rbp', new Var(uint64(ctx.rbp.toString()), 'rbp')],
          ['rsi', new Var(uint64(ctx.rsi.toString()), 'rsi')],
          ['rdi', new Var(uint64(ctx.rdi.toString()), 'rdi')],
          ['r8', new Var(uint64(ctx.r8.toString()), 'r8')],
          ['r9', new Var(uint64(ctx.r9.toString()), 'r9')],
          ['r10', new Var(uint64(ctx.r10.toString()), 'r10')],
          ['r11', new Var(uint64(ctx.r11.toString()), 'r11')],
          ['r12', new Var(uint64(ctx.r12.toString()), 'r12')],
          ['r13', new Var(uint64(ctx.r13.toString()), 'r13')],
          ['r14', new Var(uint64(ctx.r14.toString()), 'r14')],
          ['r15', new Var(uint64(ctx.r15.toString()), 'r15')],
          ['rip', new Var(uint64(ctx.rip.toString()), 'rip')],
          ['pc', new Var(uint64(ctx.pc.toString()), 'pc')],
          ['sp', new Var(uint64(ctx.sp.toString()), 'sp')],
        ]);
      }
      case 'arm': {
        const ctx = cpuContext as ArmCpuContext;
        return new Map([
          ['cpsr', new Var(uint64(ctx.cpsr.toString()), 'cpsr')],
          ['r0', new Var(uint64(ctx.r0.toString()), 'r0')],
          ['r1', new Var(uint64(ctx.r1.toString()), 'r1')],
          ['r2', new Var(uint64(ctx.r2.toString()), 'r2')],
          ['r3', new Var(uint64(ctx.r3.toString()), 'r3')],
          ['r4', new Var(uint64(ctx.r4.toString()), 'r4')],
          ['r5', new Var(uint64(ctx.r5.toString()), 'r5')],
          ['r6', new Var(uint64(ctx.r6.toString()), 'r6')],
          ['r7', new Var(uint64(ctx.r7.toString()), 'r7')],
          ['r8', new Var(uint64(ctx.r8.toString()), 'r8')],
          ['r9', new Var(uint64(ctx.r9.toString()), 'r9')],
          ['r10', new Var(uint64(ctx.r10.toString()), 'r10')],
          ['r11', new Var(uint64(ctx.r11.toString()), 'r11')],
          ['r12', new Var(uint64(ctx.r12.toString()), 'r12')],
          ['lr', new Var(uint64(ctx.lr.toString()), 'lr')],
          ['pc', new Var(uint64(ctx.pc.toString()), 'pc')],
          ['sp', new Var(uint64(ctx.sp.toString()), 'sp')],
        ]);
      }
      case 'arm64': {
        const ctx = cpuContext as Arm64CpuContext;
        return new Map([
          ['nzcv', new Var(uint64(ctx.nzcv.toString()), 'nzcv')],
          ['x0', new Var(uint64(ctx.x0.toString()), 'x0')],
          ['x1', new Var(uint64(ctx.x1.toString()), 'x1')],
          ['x2', new Var(uint64(ctx.x2.toString()), 'x2')],
          ['x3', new Var(uint64(ctx.x3.toString()), 'x3')],
          ['x4', new Var(uint64(ctx.x4.toString()), 'x4')],
          ['x5', new Var(uint64(ctx.x5.toString()), 'x5')],
          ['x6', new Var(uint64(ctx.x6.toString()), 'x6')],
          ['x7', new Var(uint64(ctx.x7.toString()), 'x7')],
          ['x8', new Var(uint64(ctx.x8.toString()), 'x8')],
          ['x9', new Var(uint64(ctx.x9.toString()), 'x9')],
          ['x10', new Var(uint64(ctx.x10.toString()), 'x10')],
          ['x11', new Var(uint64(ctx.x11.toString()), 'x11')],
          ['x12', new Var(uint64(ctx.x12.toString()), 'x12')],
          ['x13', new Var(uint64(ctx.x13.toString()), 'x13')],
          ['x14', new Var(uint64(ctx.x14.toString()), 'x14')],
          ['x15', new Var(uint64(ctx.x15.toString()), 'x15')],
          ['x16', new Var(uint64(ctx.x16.toString()), 'x16')],
          ['x17', new Var(uint64(ctx.x17.toString()), 'x17')],
          ['x18', new Var(uint64(ctx.x18.toString()), 'x18')],
          ['x19', new Var(uint64(ctx.x19.toString()), 'x19')],
          ['x20', new Var(uint64(ctx.x20.toString()), 'x20')],
          ['x21', new Var(uint64(ctx.x21.toString()), 'x21')],
          ['x22', new Var(uint64(ctx.x22.toString()), 'x22')],
          ['x23', new Var(uint64(ctx.x23.toString()), 'x23')],
          ['x24', new Var(uint64(ctx.x24.toString()), 'x24')],
          ['x25', new Var(uint64(ctx.x25.toString()), 'x25')],
          ['x26', new Var(uint64(ctx.x26.toString()), 'x26')],
          ['x27', new Var(uint64(ctx.x27.toString()), 'x27')],
          ['x28', new Var(uint64(ctx.x28.toString()), 'x28')],
          ['fp', new Var(uint64(ctx.fp.toString()), 'fp')],
          ['lr', new Var(uint64(ctx.lr.toString()), 'lr')],
          ['pc', new Var(uint64(ctx.pc.toString()), 'pc')],
          ['sp', new Var(uint64(ctx.sp.toString()), 'sp')],
        ]);
      }
      case 'mips':
      default:
        throw new Error(`unknown or unsupported architecture: ${Process.arch}`);
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
        throw new Error(`unknown or unsupported architecture: ${Process.arch}`);
    }
  }

  public static all(): [string, Var][] {
    const result: [string, Var][] = [];

    if (this.isClear())
      throw new Error('registers not available outside of a breakpoint');

    if (this.ctx === null) {
      if (this.pc !== null) {
        result.push([
          Regs.PC_NAME,
          new Var(uint64(this.pc.toString()), Regs.PC_NAME),
        ]);
      }
    } else {
      const regs = Array.from(this.getRegs(this.ctx).entries());
      regs.forEach(r => result.push(r));
    }

    for (const [k, v] of Object.entries(this.pseudoRegs)) {
      if (v === null) continue;
      result.push([k, v]);
    }

    return result;
  }

  private static isClear() {
    if (this.ctx !== null) return false;
    if (this.pc !== null) return false;
    if (Object.values(this.pseudoRegs).some(v => v !== null)) return false;
    return true;
  }

  public static setContext(ctx: CpuContext) {
    this.ctx = ctx;
  }

  public static getContext(): CpuContext | null {
    return this.ctx;
  }

  public static clear() {
    for (const name of Object.keys(this.pseudoRegs)) {
      const key = name as PseudoRegNames;
      this.pseudoRegs[key] = null;
    }
    this.pc = null;
    this.retVal = null;
  }
}
