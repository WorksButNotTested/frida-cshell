import { CmdLetBase } from '../../commands/cmdlet.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { Format } from '../../misc/format.js';
import { BlockTrace } from '../../traces/block.js';
import { CallTrace } from '../../traces/call.js';
import { CoverageTrace } from '../../traces/coverage/trace.js';
import { Trace, TraceData, Traces } from '../../traces/trace.js';
import { Var } from '../../vars/var.js';

abstract class TraceBaseCmdLet<T extends Trace, M> extends CmdLetBase {
  private static readonly STOP_CHAR: string = 'x';
  category = 'trace';

  protected abstract traceType: string;
  protected abstract runCreate(tokens: Token[]): Var | null;
  protected abstract runUnsuppress(tokens: Token[]): Var | null;
  protected abstract getState(trace: T): string;
  protected abstract onShow(trace: T, meta: M): void;
  protected abstract onStop(trace: T, meta: M): void;
  protected abstract formatMeta(meta: M): string;
  protected abstract getFilename(trace: T, meta: M): string | null;

  protected byIndex: Map<number, [T, M]> = new Map<number, [T, M]>();

  public runSync(tokens: Token[]): Var {
    const retShow = this.runShow(tokens);
    if (retShow !== null) return retShow;

    const retStop = this.runStop(tokens);
    if (retStop !== null) return retStop;

    const retDelete = this.runDelete(tokens);
    if (retDelete !== null) return retDelete;

    const retCreate = this.runCreate(tokens);
    if (retCreate !== null) return retCreate;

    const retStart = this.runUnsuppress(tokens);
    if (retStart !== null) return retStart;

    return this.usage();
  }

  private printTrace(trace: T, meta: M, index: number) {
    const state = this.getState(trace);
    const detail = trace.data().details();
    const metaString = this.formatMeta(meta);
    const tids = trace.threads();
    if (tids.length === 1) {
      const tid = tids[0] as number;
      Output.writeln(
        [
          `${Output.green(index.toString().padStart(3, ' '))}`,
          `thread:`,
          Output.blue(tid.toString()),
          `state:`,
          `[${state}]`,
          detail,
          metaString,
        ].join(' '),
      );
    } else {
      Output.writeln(
        [
          `${Output.green(index.toString().padStart(3, ' '))}`,
          `multiple threads, state:`,
          `[${state}]`,
          detail,
          metaString,
        ].join(' '),
      );
    }
  }

  private runShow(tokens: Token[]): Var | null {
    const vars = this.transformOptional(tokens, [], [this.parseIndex]);
    if (vars === null) return null;
    const [_, [index]] = vars as [[], [number | null]];

    if (index === null) {
      Output.writeln(
        `${Output.blue(this.traceType)} ${Output.blue('traces')}:`,
      );
      this.byIndex.forEach((value, index) => {
        const [trace, meta] = value;
        this.printTrace(trace, meta, index);
      });
      return Var.ZERO;
    } else {
      const value = this.byIndex.get(index);
      if (value === undefined) {
        Output.writeln(`trace #${index} not found`);
        return Var.ZERO;
      } else {
        const [trace, meta] = value;
        this.printTrace(trace, meta, index);
        if (trace.isStopped()) {
          this.onShow(trace, meta);
        } else {
          Output.writeln(`trace #${index} is still running`);
        }
        const tids = trace.threads();
        if (tids.length === 1) {
          const id = tids[0] as number;
          return new Var(uint64(id), `Thread: ${id}`);
        } else {
          return Var.ZERO;
        }
      }
    }
  }

  private runStop(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseIndex, this.parseStop]);
    if (vars === null) return null;
    const [index, _] = vars as [number, string];

    const value = this.byIndex.get(index);
    if (value === undefined) {
      Output.writeln(`trace #${index} not found`);
      return Var.ZERO;
    } else {
      const [trace, meta] = value;
      if (trace.isStopped()) {
        Output.writeln(`trace #${index} is already stopped`);
      } else {
        trace.threads().forEach(t => Traces.delete(t));
        this.onStop(trace, meta);
        Output.writeln(`trace #${index} stopped`);
      }
      const filename = this.getFilename(trace, meta);
      if (filename === null) {
        return Var.ZERO;
      } else {
        return new Var(filename);
      }
    }
  }

  protected parseStop(token: Token): string | null {
    const literal = token.getLiteral();
    if (literal !== TraceBaseCmdLet.STOP_CHAR) return null;
    return literal;
  }

  private runDelete(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [this.parseIndex, this.parseDelete]);
    if (vars === null) return null;
    const [index, _] = vars as [number, string];

    const value = this.byIndex.get(index);
    if (value === undefined) {
      Output.writeln(`trace #${index} not found`);
      return Var.ZERO;
    } else {
      const [trace, meta] = value;
      const stopped = trace.isStopped();
      trace.threads().forEach(t => Traces.delete(t));
      if (!stopped) {
        this.onStop(trace, meta);
        this.onShow(trace, meta);
      }
      this.byIndex.delete(index);
      Output.writeln(`trace #${index} deleted`);
      const filename = this.getFilename(trace, meta);
      if (filename === null) {
        return Var.ZERO;
      } else {
        return new Var(filename);
      }
    }
  }

  protected addTrace(trace: T, meta: M): number {
    let idx = 1;
    while (true) {
      if (!this.byIndex.has(idx)) {
        this.byIndex.set(idx, [trace, meta]);
        return idx;
      }
      idx++;
    }
  }

  protected usageCreate(): string {
    return `
${this.name} tid depth - start a ${this.traceType} trace
  tid          the thread to trace
  depth        the depth to trace

${this.name} tid depth file - start a ${this.traceType} trace
  tid          the thread to trace
  depth        the depth to trace
  file         the file to log to`;
  }

  public usage(): Var {
    const create = this.usageCreate();
    const usage: string = `Usage: ${this.name}

${Output.bold('show:')}

${this.name} - show all ${this.traceType} traces

${this.name} ${CmdLetBase.NUM_CHAR}n - show ${this.traceType} trace with the given index
  ${CmdLetBase.NUM_CHAR}n           the index of the trace to display

${Output.bold('create:')}
${create}

${Output.bold('stop:')}

${this.name} ${CmdLetBase.NUM_CHAR}n ${TraceBaseCmdLet.STOP_CHAR} - stop ${this.traceType} trace with the given index
  ${CmdLetBase.NUM_CHAR}n           the index of the trace to stop

${Output.bold('delete:')}

${this.name} ${CmdLetBase.NUM_CHAR}n ${CmdLetBase.DELETE_CHAR} - delete ${this.traceType} trace with the given index
  ${CmdLetBase.NUM_CHAR}n           the index of the trace to stop`;

    Output.writeln(usage);
    return Var.ZERO;
  }
}

type TraceCmdLetMeta = { fileName: string | null; file: File | null };

abstract class TraceCmdLet<T extends Trace> extends TraceBaseCmdLet<
  T,
  TraceCmdLetMeta
> {
  protected abstract createTrace(threadid: number, depth: number): T;

  protected runCreate(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar, this.parseVar],
      [this.parseString],
    );
    if (vars === null) return null;
    const [[tid, depth], [fileName]] = vars as [[Var, Var], [string | null]];

    Output.debug(`fileName: ${fileName}`);

    const threadid = tid.toU64().toNumber();
    if (fileName === null) {
      const meta = { fileName: null, file: null };
      const trace = this.createTrace(threadid, depth.toU64().toNumber());
      const id = this.addTrace(trace, meta);
      Output.writeln(`Created trace: #${id}`);
      return Var.fromId(id);
    } else {
      const file = new File(fileName, 'w+');
      const meta = { fileName: fileName, file: file };
      const trace = this.createTrace(threadid, depth.toU64().toNumber());
      const id = this.addTrace(trace, meta);
      Output.writeln(`Created trace: #${id}`);
      return Var.fromId(id);
    }
  }

  protected runUnsuppress(_tokens: Token[]): Var | null {
    return null;
  }

  protected override getState(trace: T): string {
    const state = trace.isStopped()
      ? Output.red('stopped')
      : Output.green('running');
    return state;
  }

  protected override onShow(trace: Trace, meta: TraceCmdLetMeta): void {
    if (meta.file === null) {
      trace
        .data()
        .lines()
        .slice(0, TraceData.MAX_LINES)
        .forEach(l => {
          Output.writeln(l);
        });
    } else {
      Output.writeln(`\tTrace data has been written to: ${meta.fileName}`);
    }
  }

  protected override onStop(trace: Trace, meta: TraceCmdLetMeta): void {
    if (meta.file === null) return;
    Output.writeln(Output.yellow('processing...'));
    const lines = trace.data().lines();
    let last = 0;
    Output.write(
      `${Output.yellow('progress')} ${Output.blue(last.toString())}${Output.blue('%')}`,
    );
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] as string;
      const current = Math.floor((i * 100) / lines.length);
      if (current > last) {
        Output.clearLine();
        Output.write(
          `${Output.yellow('progress')} ${Output.blue(current.toString())}${Output.blue('%')}`,
        );
        last = current;
      }
      meta.file.write(`${Format.removeColours(line)}\n`);
    }
    meta.file.flush();
    const size = meta.file.tell();
    meta.file.close();
    Output.writeln();
    Output.writeln(
      `\tWriting trace to: ${meta.fileName}, ${Format.toSize(size)} bytes`,
    );
  }

  protected override formatMeta(meta: TraceCmdLetMeta): string {
    if (meta.fileName === null) return '';
    return `fileName: ${Output.blue(meta.fileName)}`;
  }

  protected override getFilename(
    _trace: Trace,
    meta: TraceCmdLetMeta,
  ): string | null {
    return meta.fileName;
  }
}

export class TraceCallCmdLet extends TraceCmdLet<CallTrace> {
  name = 'tc';
  help = 'traces calls for the given thread';
  protected traceType: string = 'call';

  protected override createTrace(threadid: number, depth: number): CallTrace {
    return CallTrace.create(threadid, depth);
  }
}

export class TraceBlockCmdLet extends TraceCmdLet<BlockTrace> {
  name = 'tb';
  help = 'traces blocks for the given thread';
  protected traceType: string = 'block';

  protected override createTrace(threadid: number, depth: number): BlockTrace {
    return BlockTrace.create(threadid, depth, false);
  }
}

export class TraceUniqueBlockCmdLet extends TraceCmdLet<BlockTrace> {
  name = 'tbu';
  help = 'traces unique blocks for the given thread';
  protected traceType: string = 'unique block';

  protected override createTrace(threadid: number, depth: number): BlockTrace {
    return BlockTrace.create(threadid, depth, true);
  }
}

type TraceCoverageCmdLetMeta = { modulePath: string | null };

export class TraceCoverageCmdLet extends TraceBaseCmdLet<
  CoverageTrace,
  TraceCoverageCmdLetMeta
> {
  name = 'c';
  help = 'traces coverage for the given thread';
  protected traceType: string = 'coverage';

  protected static readonly SUPPRESS_CHAR: string = '!';

  protected override usageCreate(): string {
    return `
${this.name} tid file [!] - start a ${this.traceType} trace
  tid          the thread to trace [or '*' for all threads]
  file         the file to log to
  [!]          start the trace in suppressed mode
  
${this.name} tid file mod [!] - start a ${this.traceType} trace
  tid          the thread to trace [or '*' for all threads]
  file         the file to log to
  mod          the absolute path of the module to trace
  [!]          start the trace in suppressed mode`;
  }

  protected runCreate(tokens: Token[]): Var | null {
    const retWithoutModule = this.runCreateWithoutModule(tokens);
    if (retWithoutModule !== null) return retWithoutModule;

    const retWithModule = this.runCreateWithModule(tokens);
    if (retWithModule !== null) return retWithModule;

    return null;
  }

  protected runCreateWithModule(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseNumberOrAll, this.parseString, this.parseLiteral],
      [this.parseSuppressedOptional],
    );
    if (vars === null) return null;
    const [[threadid, fileName, modulePath], [suppressed]] = vars as [
      [number, string, string],
      [boolean | null | undefined],
    ];

    if (suppressed === undefined) throw new Error('suppressed field malformed');

    Output.debug(`fileName: ${fileName}`);
    Output.debug(
      `suppressed: ${suppressed ? Output.red('suppressed') : Output.green('unsupressed')} (${suppressed})`,
    );

    const trace = CoverageTrace.create(
      threadid,
      fileName,
      modulePath,
      suppressed ?? false,
    );
    const id = this.addTrace(trace, { modulePath });
    Output.writeln(`Created trace: #${id}`);

    return Var.fromId(id);
  }

  protected runCreateWithoutModule(tokens: Token[]): Var | null {
    const vars = this.transformOptional(
      tokens,
      [this.parseNumberOrAll, this.parseString],
      [this.parseSuppressedOptional],
    );
    if (vars === null) return null;
    const [[threadid, fileName], [suppressed]] = vars as [
      [number, string],
      [boolean | null | undefined],
    ];

    /* The last field may be the module name */
    if (suppressed === undefined) return null;

    Output.debug(`fileName: ${fileName}`);
    Output.debug(
      `suppressed: ${suppressed ? Output.red('suppressed') : Output.green('unsupressed')} (${suppressed})`,
    );

    const trace = CoverageTrace.create(
      threadid,
      fileName,
      null,
      suppressed ?? false,
    );
    const id = this.addTrace(trace, { modulePath: null });
    Output.writeln(`Created trace: #${id}`);

    return Var.fromId(id);
  }

  protected runUnsuppress(tokens: Token[]): Var | null {
    const vars = this.transform(tokens, [
      this.parseIndex,
      this.parseSuppressed,
    ]);
    if (vars === null) return null;
    const [index, _suppressed] = vars as [number, string];

    const value = this.byIndex.get(index);
    if (value === undefined) {
      Output.writeln(`trace #${index} not found`);
      return Var.ZERO;
    } else {
      const [trace, _meta] = value;
      if (trace.isSuppressed()) {
        trace.unsuppress();
        Output.writeln(`trace #${index} unsuppressed`);
      } else {
        Output.writeln(`trace #${index} is already unsupressed`);
      }
      return Var.fromId(index);
    }
  }

  protected parseSuppressed(token: Token): string | null {
    const literal = token.getLiteral();
    if (literal !== TraceCoverageCmdLet.SUPPRESS_CHAR) return null;
    return literal;
  }

  protected parseSuppressedOptional(token: Token): boolean | undefined | null {
    const literal = token.getLiteral();
    if (literal !== TraceCoverageCmdLet.SUPPRESS_CHAR) return undefined;
    return true;
  }

  protected override getState(trace: CoverageTrace): string {
    if (trace.isStopped()) {
      return Output.red('stopped');
    } else if (trace.isSuppressed()) {
      return Output.yellow('suppressed');
    } else {
      return Output.green('running');
    }
  }

  protected override onShow(
    trace: CoverageTrace,
    _meta: TraceCoverageCmdLetMeta,
  ): void {
    const filename = trace.data().getFileName();
    Output.writeln(`\tTrace data has been written to: ${filename}`);
  }

  protected override onStop(
    trace: CoverageTrace,
    _meta: TraceCoverageCmdLetMeta,
  ): void {
    const filename = trace.data().getFileName();
    const size = trace.data().getSize();
    Output.writeln(
      `\tWriting trace to: ${filename}, ${Format.toSize(size)} bytes`,
    );
  }

  protected override formatMeta(meta: TraceCoverageCmdLetMeta): string {
    if (meta.modulePath === null) return '';
    return `modulePath: ${Output.blue(meta.modulePath)}`;
  }

  protected override getFilename(
    trace: CoverageTrace,
    _meta: TraceCoverageCmdLetMeta,
  ): string | null {
    return trace.data().getFileName();
  }
}
