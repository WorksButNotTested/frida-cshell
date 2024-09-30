import { CmdLet } from './cmdlet.js';
import { DumpCmdLet } from '../cmdlets/data/dump.js';
import { DumpStringCmdLet } from '../cmdlets/data/string.js';
import { ExitCmdLet } from '../cmdlets/misc/exit.js';
import { SymCmdLet } from '../cmdlets/memory/sym.js';
import { ReadCmdLet } from '../cmdlets/data/read.js';
import { WriteCmdLet } from '../cmdlets/data/write.js';
import { AssemblyCmdLet } from '../cmdlets/data/assembly.js';
import { VarCmdLet } from '../cmdlets/misc/var.js';
import { VmCmdLet } from '../cmdlets/memory/vm.js';
import { ModCmdLet } from '../cmdlets/modules/mod.js';
import { ThreadCmdLet } from '../cmdlets/thread/thread.js';
import { BtCmdLet } from '../cmdlets/thread/bt.js';
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
  EndianCmdLet,
  EqCmdLet,
  NeCmdLet,
  FalseCmdLet,
  TrueCmdLet,
} from '../cmdlets/math/math.js';
import { HistoryCmdLet } from '../cmdlets/misc/history.js';
import { HelpCmdLet } from '../cmdlets/misc/help.js';
import { CopyCmdLet } from '../cmdlets/data/copy.js';
import {
  FunctionEntryBpCmdLet,
  FunctionExitBpCmdLet,
  BlockTraceBpCmdLet,
  CallTraceBpCmdLet,
  UniqueBlockTraceBpCmdLet,
  CoverageBpCmdLet,
  InsnBpCmdLet,
  ReadBpCmdLet,
  WriteBpCmdLet,
} from '../cmdlets/breakpoints/bp.js';
import { RegCmdLet } from '../cmdlets/breakpoints/reg.js';
import { LdCmdLet } from '../cmdlets/modules/ld.js';
import { FdCmdLet } from '../cmdlets/files/fd.js';
import { JsCmdLet } from '../cmdlets/development/js.js';
import { PrintCmdLet } from '../cmdlets/misc/print.js';
import { ShCmdLet } from '../cmdlets/misc/sh.js';
import { SrcCmdLet } from '../cmdlets/files/src.js';
import { DebugCmdLet } from '../cmdlets/development/debug.js';
import { GrepCmdLet } from '../cmdlets/misc/grep.js';
import { CatCmdLet } from '../cmdlets/files/cat.js';
import { LogCmdLet } from '../cmdlets/misc/log.js';
import { HotCmdLet } from '../cmdlets/thread/hot.js';
import {
  TraceCallCmdLet,
  TraceBlockCmdLet,
  TraceUniqueBlockCmdLet,
  TraceCoverageCmdLet,
} from '../cmdlets/trace/trace.js';
import { MacroCmdLet } from '../cmdlets/misc/macro.js';

export class CmdLets {
  private static byName: Map<string, CmdLet> = new Map<string, CmdLet>();

  static {
    this.registerCmdletType(AddCmdLet);
    this.registerCmdletType(AndCmdLet);
    this.registerCmdletType(SubCmdLet);
    this.registerCmdletType(AssemblyCmdLet);
    this.registerCmdletType(BlockTraceBpCmdLet);
    this.registerCmdletType(BtCmdLet);
    this.registerCmdletType(CallTraceBpCmdLet);
    this.registerCmdletType(CatCmdLet);
    this.registerCmdletType(CopyCmdLet);
    this.registerCmdletType(CoverageBpCmdLet);
    this.registerCmdletType(DivCmdLet);
    this.registerCmdletType(DumpCmdLet);
    this.registerCmdletType(DumpStringCmdLet);
    this.registerCmdletType(EndianCmdLet);
    this.registerCmdletType(EqCmdLet);
    this.registerCmdletType(ExitCmdLet);
    this.registerCmdletType(FalseCmdLet);
    this.registerCmdletType(FdCmdLet);
    this.registerCmdletType(GrepCmdLet);
    this.registerCmdletType(FunctionEntryBpCmdLet);
    this.registerCmdletType(FunctionExitBpCmdLet);
    this.registerCmdletType(HelpCmdLet);
    this.registerCmdletType(HistoryCmdLet);
    this.registerCmdletType(HotCmdLet);
    this.registerCmdletType(InsnBpCmdLet);
    this.registerCmdletType(JsCmdLet);
    this.registerCmdletType(LdCmdLet);
    this.registerCmdletType(LogCmdLet);
    this.registerCmdletType(OrCmdLet);
    this.registerCmdletType(ReadCmdLet);
    this.registerCmdletType(MacroCmdLet);
    this.registerCmdletType(ModCmdLet);
    this.registerCmdletType(MulCmdLet);
    this.registerCmdletType(NeCmdLet);
    this.registerCmdletType(NotCmdLet);
    this.registerCmdletType(PrintCmdLet);
    this.registerCmdletType(ReadBpCmdLet);
    this.registerCmdletType(RegCmdLet);
    this.registerCmdletType(ShCmdLet);
    this.registerCmdletType(ShlCmdLet);
    this.registerCmdletType(ShrCmdLet);
    this.registerCmdletType(SrcCmdLet);
    this.registerCmdletType(SymCmdLet);
    this.registerCmdletType(ThreadCmdLet);
    this.registerCmdletType(TraceBlockCmdLet);
    this.registerCmdletType(TraceCallCmdLet);
    this.registerCmdletType(TraceCoverageCmdLet);
    this.registerCmdletType(TraceUniqueBlockCmdLet);
    this.registerCmdletType(TrueCmdLet);
    this.registerCmdletType(UniqueBlockTraceBpCmdLet);
    this.registerCmdletType(VarCmdLet);
    this.registerCmdletType(DebugCmdLet);
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
