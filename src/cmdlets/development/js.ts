import { Bp } from '../../breakpoints/bp.js';
import { Bps } from '../../breakpoints/bps.js';
import { MemoryBps } from '../../breakpoints/memory.js';
import { Regs } from '../../breakpoints/regs.js';
import { CmdLet } from '../../commands/cmdlet.js';
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
import {
  FunctionEntryBpCmdLet,
  FunctionExitBpCmdLet,
  InsnBpCmdLet,
  ReadBpCmdLet,
  WriteBpCmdLet,
} from '../breakpoints/bp.js';
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
  MulCmdLet,
  NotCmdLet,
  OrCmdLet,
  ShlCmdLet,
  ShrCmdLet,
  SubCmdLet,
  XorCmdLet,
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

export class JsCmdLet extends CmdLet {
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
      Bp: Bp,
      Bps: Bps,
      BtCmdLet: BtCmdLet,
      CatCmdLet: CatCmdLet,
      CharCode: CharCode,
      CmdLets: CmdLets,
      Command: Command,
      CopyCmdLet: CopyCmdLet,
      DivCmdLet: DivCmdLet,
      DumpCmdLet: DumpCmdLet,
      ExitCmdLet: ExitCmdLet,
      FdCmdLet: FdCmdLet,
      Format: Format,
      FunctionEntryBpCmdLet: FunctionEntryBpCmdLet,
      FunctionExitBpCmdLet: FunctionExitBpCmdLet,
      GrepCmdLet: GrepCmdLet,
      HelpCmdLet: HelpCmdLet,
      History: History,
      HistoryCmdLet: HistoryCmdLet,
      HotCmdLet: HotCmdLet,
      Input: Input,
      InsnBpCmdLet: InsnBpCmdLet,
      LdCmdLet: LdCmdLet,
      Line: Line,
      LogCmdLet: LogCmdLet,
      MacroCmdLet: MacroCmdLet,
      Mem: Mem,
      MemoryBps: MemoryBps,
      ModCmdLet: ModCmdLet,
      MulCmdLet: MulCmdLet,
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
    const cmdlet = func(gThis);
    if (cmdlet !== undefined) {
      Output.writeln(`Found cmdlet: ${cmdlet.name}`);
      CmdLets.registerCmdlet(cmdlet);
    }

    return Var.ZERO;
  }

  public usage(): Var {
    Output.writeln(JsCmdLet.USAGE);
    return Var.ZERO;
  }
}
