import { CmdLet } from './cmdlet.js';
import { DumpCmdLet } from './cmdlets/dump.js';
import { ExitCmdLet } from './cmdlets/exit.js';
import { SymCmdLet } from './cmdlets/sym.js';
import {
  Read1CmdLet,
  Read2CmdLet,
  Read4CmdLet,
  Read8CmdLet,
} from './cmdlets/read.js';
import {
  Write1CmdLet,
  Write2CmdLet,
  Write4CmdLet,
  Write8CmdLet,
} from './cmdlets/write.js';
import { AssemblyCmdLet } from './cmdlets/assembly.js';
import { VarCmdLet } from './cmdlets/var.js';
import { VmCmdLet } from './cmdlets/vm.js';
import { ModCmdLet } from './cmdlets/mod.js';
import { ThreadCmdLet } from './cmdlets/thread.js';
import { BtCmdLet } from './cmdlets/bt.js';
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
} from './cmdlets/math.js';
import { HistoryCmdLet } from './cmdlets/history.js';
import { HelpCmdLet } from './cmdlets/help.js';
import { CopyCmdLet } from './cmdlets/copy.js';
import { BpCmdLet, FunctionEntryBpCmdLet, InsnBpCmdLet } from './cmdlets/bp.js';
import { RegCmdLet } from './cmdlets/reg.js';
import { LdCmdLet } from './cmdlets/ld.js';

export class CmdLets {
  public static getByName(name: string): CmdLet | undefined {
    const cmdlet = this.byName.get(name);
    return cmdlet;
  }

  public static all(): CmdLet[] {
    return Array.from(this.byName.values());
  }

  private static byName: Map<string, CmdLet> = new Map<string, CmdLet>();

  static {
    this.register(AddCmdLet);
    this.register(AndCmdLet);
    this.register(SubCmdLet);
    this.register(AssemblyCmdLet);
    this.register(BpCmdLet);
    this.register(BtCmdLet);
    this.register(DivCmdLet);
    this.register(CopyCmdLet);
    this.register(DumpCmdLet);
    this.register(ExitCmdLet);
    this.register(FunctionEntryBpCmdLet);
    this.register(HelpCmdLet);
    this.register(HistoryCmdLet);
    this.register(InsnBpCmdLet);
    this.register(LdCmdLet);
    this.register(OrCmdLet);
    this.register(Read1CmdLet);
    this.register(Read2CmdLet);
    this.register(Read4CmdLet);
    this.register(Read8CmdLet);
    this.register(ModCmdLet);
    this.register(MulCmdLet);
    this.register(NotCmdLet);
    this.register(RegCmdLet);
    this.register(ShlCmdLet);
    this.register(ShrCmdLet);
    this.register(SymCmdLet);
    this.register(ThreadCmdLet);
    this.register(VarCmdLet);
    this.register(VmCmdLet);
    this.register(Write1CmdLet);
    this.register(Write2CmdLet);
    this.register(Write4CmdLet);
    this.register(Write8CmdLet);
    this.register(XorCmdLet);
  }

  private static register<T extends CmdLet>(cmdletClass: new () => T) {
    const cmdlet = new cmdletClass();
    this.byName.set(cmdlet.name, cmdlet);
  }
}
