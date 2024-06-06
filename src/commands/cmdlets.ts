import { CmdLet } from './cmdlet.js';
import { DumpCmdLet } from '../cmdlets/dump.js';
import { ExitCmdLet } from '../cmdlets/exit.js';
import { SymCmdLet } from '../cmdlets/sym.js';
import { ReadCmdLet } from '../cmdlets/read.js';
import { WriteCmdLet } from '../cmdlets/write.js';
import { AssemblyCmdLet } from '../cmdlets/assembly.js';
import { VarCmdLet } from '../cmdlets/var.js';
import { VmCmdLet } from '../cmdlets/vm.js';
import { ModCmdLet } from '../cmdlets/mod.js';
import { ThreadCmdLet } from '../cmdlets/thread.js';
import { BtCmdLet } from '../cmdlets/bt.js';
import {
  AddCmdLet,
  SubCmdLet,
  MulCmdLet,
  DivCmdLet,
  OrCmdLet,
  AndCmdLet,
  XorCmdLet,
  ShlCmdLet,
  ShrCmdLet,
  NotCmdLet,
} from '../cmdlets/math.js';
import { HistoryCmdLet } from '../cmdlets/history.js';
import { HelpCmdLet } from '../cmdlets/help.js';
import { CopyCmdLet } from '../cmdlets/copy.js';
import {
  FunctionEntryBpCmdLet,
  FunctionExitBpCmdLet,
  InsnBpCmdLet,
  ReadBpCmdLet,
  WriteBpCmdLet,
} from '../cmdlets/bp.js';
import { RegCmdLet } from '../cmdlets/reg.js';
import { LdCmdLet } from '../cmdlets/ld.js';
import { FdCmdLet } from '../cmdlets/fd.js';
import { SrcCmdLet } from '../cmdlets/src.js';
import { PrintCmdLet } from '../cmdlets/print.js';

export class CmdLets {
  private static byName: Map<string, CmdLet> = new Map<string, CmdLet>();

  static {
    this.registerCmdletType(AddCmdLet);
    this.registerCmdletType(AndCmdLet);
    this.registerCmdletType(SubCmdLet);
    this.registerCmdletType(AssemblyCmdLet);
    this.registerCmdletType(BtCmdLet);
    this.registerCmdletType(DivCmdLet);
    this.registerCmdletType(CopyCmdLet);
    this.registerCmdletType(DumpCmdLet);
    this.registerCmdletType(ExitCmdLet);
    this.registerCmdletType(FdCmdLet);
    this.registerCmdletType(FunctionEntryBpCmdLet);
    this.registerCmdletType(FunctionExitBpCmdLet);
    this.registerCmdletType(HelpCmdLet);
    this.registerCmdletType(HistoryCmdLet);
    this.registerCmdletType(InsnBpCmdLet);
    this.registerCmdletType(LdCmdLet);
    this.registerCmdletType(OrCmdLet);
    this.registerCmdletType(ReadCmdLet);
    this.registerCmdletType(ModCmdLet);
    this.registerCmdletType(MulCmdLet);
    this.registerCmdletType(NotCmdLet);
    this.registerCmdletType(PrintCmdLet);
    this.registerCmdletType(ReadBpCmdLet);
    this.registerCmdletType(RegCmdLet);
    this.registerCmdletType(ShlCmdLet);
    this.registerCmdletType(ShrCmdLet);
    this.registerCmdletType(SrcCmdLet);
    this.registerCmdletType(SymCmdLet);
    this.registerCmdletType(ThreadCmdLet);
    this.registerCmdletType(VarCmdLet);
    this.registerCmdletType(VmCmdLet);
    this.registerCmdletType(WriteCmdLet);
    this.registerCmdletType(WriteBpCmdLet);
    this.registerCmdletType(XorCmdLet);
  }

  private static registerCmdletType<T extends CmdLet>(
    cmdletClass: new () => T,
  ) {
    const cmdlet = new cmdletClass();
    if (cmdlet.isSupported()) this.byName.set(cmdlet.name, cmdlet);
  }

  public static all(): CmdLet[] {
    return Array.from(this.byName.values());
  }

  public static getByName(name: string): CmdLet | null {
    const cmdlet = this.byName.get(name);
    return cmdlet ?? null;
  }

  public static registerCmdlet(cmdlet: CmdLet) {
    if (cmdlet.isSupported()) this.byName.set(cmdlet.name, cmdlet);
  }
}
