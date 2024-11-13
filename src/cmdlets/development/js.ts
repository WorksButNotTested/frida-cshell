import { Bp } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import { BpMemory } from '../../breakpoints/memory.js';
import { Regs } from '../../breakpoints/regs.js';
import { CmdLetBase, CmdLet } from '../../commands/cmdlet.js';
import { CmdLets } from '../../commands/cmdlets.js';
import { Command } from '../../commands/command.js';
import { CharCode, Vt } from '../../io/char.js';
import { Input } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Parser } from '../../io/parser.js';
import { Token } from '../../io/token.js';
import { Mem } from '../../memory/mem.js';
import { Overlay } from '../../memory/overlay.js';
import { Base64 } from '../../misc/base64.js';
import { Format } from '../../misc/format.js';
import { Numeric } from '../../misc/numeric.js';
import { History } from '../../terminal/history.js';
import { Line } from '../../terminal/line.js';
import { Var } from '../../vars/var.js';
import { Vars } from '../../vars/vars.js';
import { AssemblyCmdLet } from '../data/assembly.js';
import { ReadBpCmdLet, WriteBpCmdLet } from '../breakpoints/mem.js';
import {
  InsnBpCmdLet,
  FunctionEntryBpCmdLet,
  FunctionExitBpCmdLet,
  CoverageBpCmdLet,
} from '../breakpoints/code.js';
import {
  BlockTraceBpCmdLet,
  CallTraceBpCmdLet,
  UniqueBlockTraceBpCmdLet,
} from '../breakpoints/trace.js';
import { BtCmdLet } from '../thread/bt.js';
import { CopyCmdLet } from '../data/copy.js';
import { DumpCmdLet } from '../data/dump.js';
import { ExitCmdLet } from '../misc/exit.js';
import { FdCmdLet } from '../files/fd.js';
import { HelpCmdLet } from '../misc/help.js';
import { HistoryCmdLet } from '../misc/history.js';
import { LdCmdLet } from '../modules/ld.js';
import {
  AddCmdLet,
  AndCmdLet,
  DivCmdLet,
  EqCmdLet,
  MulCmdLet,
  NeCmdLet,
  NotCmdLet,
  OrCmdLet,
  ShlCmdLet,
  ShrCmdLet,
  SubCmdLet,
  XorCmdLet,
  TrueCmdLet,
  FalseCmdLet,
  GreaterThanCmdLet,
  GreaterThanEqualsCmdLet,
  LessThanCmdLet,
  LessThanEqualsCmdLet,
} from '../math/math.js';
import { ModCmdLet } from '../modules/mod.js';
import { ReadCmdLet } from '../data/read.js';
import { RegCmdLet } from '../breakpoints/reg.js';
import { SymCmdLet } from '../memory/sym.js';
import { ThreadCmdLet } from '../thread/thread.js';
import { VarCmdLet } from '../misc/var.js';
import { VmCmdLet } from '../memory/vm.js';
import { WriteCmdLet } from '../data/write.js';
import { GrepCmdLet } from '../misc/grep.js';
import { CatCmdLet } from '../files/cat.js';
import { LogCmdLet } from '../misc/log.js';
import { HotCmdLet } from '../thread/hot.js';
import {
  TraceCallCmdLet,
  TraceBlockCmdLet,
  TraceUniqueBlockCmdLet,
  TraceCoverageCmdLet,
} from '../trace/trace.js';
import { MacroCmdLet } from '../misc/macro.js';
import { ReplaceCmdLet } from '../breakpoints/replace.js';
import { EchoCmdLet } from '../misc/echo.js';
import { CorpseCmdLet } from '../misc/corpse/corpse.js';

export class JsCmdLet extends CmdLetBase {
  name = 'js';
  category = 'development';
  help = 'load script';

  private static readonly USAGE: string = `Usage: js

js path - load commandlet JS script
  path      the absolute path of the commandlet script to load (note that paths with spaces must be quoted)`;

  public runSync(tokens: Token[]): Var {
    const vars = this.transform(tokens, [this.parseLiteral]);
    if (vars === null) return this.usage();
    let [name] = vars as [string];

    if (name.length > 1 && name.startsWith('"') && name.endsWith('"')) {
      name = name.slice(1, name.length - 1);
    }

    Output.writeln(`Loading: ${name}`);

    const gThis = {
      AddCmdLet: AddCmdLet,
      AndCmdLet: AndCmdLet,
      AssemblyCmdLet: AssemblyCmdLet,
      Base64: Base64,
      BlockTraceBpCmdLet: BlockTraceBpCmdLet,
      Bp: Bp,
      BpMemory: BpMemory,
      Bps: Bps,
      BtCmdLet: BtCmdLet,
      CallTraceBpCmdLet: CallTraceBpCmdLet,
      CatCmdLet: CatCmdLet,
      CharCode: CharCode,
      CmdLets: CmdLets,
      Command: Command,
      CopyCmdLet: CopyCmdLet,
      CorpseCmdLet: CorpseCmdLet,
      CoverageBpCmdLet: CoverageBpCmdLet,
      DivCmdLet: DivCmdLet,
      DumpCmdLet: DumpCmdLet,
      EchoCmdLet: EchoCmdLet,
      EqCmdLet: EqCmdLet,
      ExitCmdLet: ExitCmdLet,
      FalseCmdLet: FalseCmdLet,
      FdCmdLet: FdCmdLet,
      Format: Format,
      FunctionEntryBpCmdLet: FunctionEntryBpCmdLet,
      FunctionExitBpCmdLet: FunctionExitBpCmdLet,
      GreaterThanCmdLet: GreaterThanCmdLet,
      GreaterThanEqualsCmdLet: GreaterThanEqualsCmdLet,
      GrepCmdLet: GrepCmdLet,
      HelpCmdLet: HelpCmdLet,
      History: History,
      HistoryCmdLet: HistoryCmdLet,
      HotCmdLet: HotCmdLet,
      Input: Input,
      InsnBpCmdLet: InsnBpCmdLet,
      LdCmdLet: LdCmdLet,
      LessThanCmdLet: LessThanCmdLet,
      LessThanEqualsCmdLet: LessThanEqualsCmdLet,
      Line: Line,
      LogCmdLet: LogCmdLet,
      MacroCmdLet: MacroCmdLet,
      Mem: Mem,
      ModCmdLet: ModCmdLet,
      MulCmdLet: MulCmdLet,
      NeCmdLet: NeCmdLet,
      NotCmdLet: NotCmdLet,
      Numeric: Numeric,
      OrCmdLet: OrCmdLet,
      Output: Output,
      Overlay: Overlay,
      Parser: Parser,
      ReadBpCmdLet: ReadBpCmdLet,
      ReadCmdLet: ReadCmdLet,
      RegCmdLet: RegCmdLet,
      Regs: Regs,
      ReplaceCmdLet: ReplaceCmdLet,
      ShlCmdLet: ShlCmdLet,
      ShrCmdLet: ShrCmdLet,
      SrcCmdLet: JsCmdLet,
      SubCmdLet: SubCmdLet,
      SymCmdLet: SymCmdLet,
      ThreadCmdLet: ThreadCmdLet,
      TraceBlockCmdLet: TraceBlockCmdLet,
      TraceCallCmdLet: TraceCallCmdLet,
      TraceCoverageCmdLet: TraceCoverageCmdLet,
      TraceUniqueBlockCmdLet: TraceUniqueBlockCmdLet,
      Token: Token,
      TrueCmdLet: TrueCmdLet,
      UniqueBlockTraceBpCmdLet: UniqueBlockTraceBpCmdLet,
      Var: Var,
      VarCmdLet: VarCmdLet,
      Vars: Vars,
      VmCmdLet: VmCmdLet,
      Vt: Vt,
      WriteBpCmdLet: WriteBpCmdLet,
      WriteCmdLet: WriteCmdLet,
      XorCmdLet: XorCmdLet,
    };

    const script = File.readAllText(name);
    const func = new Function('gThis', `with (gThis) { ${script} }`);
    const cmdlets = func(gThis) as CmdLet[];
    if (cmdlets === undefined) {
      Output.writeln('No cmdlets found.');
      return Var.ZERO;
    }

    for (const [idx, cmdlet] of cmdlets.entries()) {
      try {
        this.checkMandatoryMembers(cmdlet);
      } catch (e) {
        Output.writeln(`error '${e}' in cmdlet ${idx}`);
        return Var.ZERO;
      }
    }

    for (const cmdlet of cmdlets) {
      Output.writeln(`Found cmdlet: ${cmdlet.name}`);
      this.addMissingMembers(cmdlet);
      CmdLets.registerCmdlet(cmdlet);
    }

    return Var.ZERO;
  }

  private checkMandatoryMembers(cmdlet: CmdLet) {
    if (cmdlet.name === undefined) {
      throw new Error('name not specified');
    }

    if (cmdlet.runSync === undefined) {
      throw new Error('runSync not specified');
    }
  }

  private addMissingMembers(cmdlet: CmdLet) {
    if (cmdlet.usage === undefined) {
      cmdlet.usage = function () {
        Output.writeln('no usage information available for this command');
        return Var.ZERO;
      };
    }

    if (cmdlet.isSupported === undefined) {
      cmdlet.isSupported = function () {
        return true;
      };
    }

    if (cmdlet.run === undefined) {
      cmdlet.run = async function (tokens: Token[]): Promise<Var> {
        return cmdlet.runSync(tokens);
      };
    }

    if (cmdlet.category === undefined) {
      cmdlet.category = 'uncategorised';
    }

    if (cmdlet.visible === undefined) {
      cmdlet.visible = true;
    }

    if (cmdlet.help === undefined) {
      cmdlet.help = `${cmdlet.name} command`;
    }
  }

  public usage(): Var {
    Output.writeln(JsCmdLet.USAGE);
    return Var.ZERO;
  }
}
