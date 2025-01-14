import { Output } from '../../io/output.js';
import { Files } from '../../misc/files.js';
import { Format } from '../../misc/format.js';
import { TraceBase, TraceData, Traces } from '../trace.js';
import { Coverage, CoverageSession } from './coverage.js';

class CoverageTraceData extends TraceData {
  private threadIds: ThreadId[];
  private filename: string;
  private file: File;
  private size: number = 0;

  public constructor(threadIds: ThreadId[], filename: string | null) {
    super();
    this.threadIds = threadIds;
    this.filename = filename ?? Files.getRandomFileName('cov');
    this.file = new File(this.filename, 'wb+');
  }

  public append(events: ArrayBuffer) {
    this.file.write(events);
    this.size += events.byteLength;
  }

  public stop(): void {
    this.file.close();
  }

  public lines(): string[] {
    if (this.threadIds.length === 1) {
      const threadId = this.threadIds[0] as number;
      return [
        [
          'Wrote coverage for thread:',
          Output.yellow(threadId.toString()),
          'to:',
          Output.green(this.filename),
        ].join(' '),
      ];
    } else {
      return [
        [
          'Wrote coverage multiple threads sto:',
          Output.green(this.filename),
        ].join(' '),
      ];
    }
  }

  public details(): string {
    return ['file:', Output.blue(this.filename)].join(' ');
  }

  public getFileName(): string {
    return this.filename;
  }

  public getSize(): number {
    return this.size;
  }
}
export class CoverageTrace extends TraceBase<CoverageTraceData> {
  private coverage: CoverageSession;

  private constructor(
    threadIds: ThreadId[],
    filename: string | null,
    modulePath: string | null,
  ) {
    const trace = new CoverageTraceData(threadIds, filename);
    super(threadIds, trace);

    let moduleFilter = Coverage.allModules;
    if (modulePath !== null) {
      moduleFilter = m => m.path === modulePath;
    }

    this.coverage = Coverage.start({
      moduleFilter: moduleFilter,
      onCoverage: (coverageData, isHeader) => {
        this.trace.append(coverageData);
        if (isHeader)
          Output.write(Output.blue(Format.toTextString(coverageData)));
      },
      threadFilter: t => threadIds.includes(t.id),
    });
  }

  public static create(
    threadId: ThreadId,
    filename: string | null,
    modulePath: string | null,
  ): CoverageTrace {
    const threadIds =
      threadId === -1 ? Process.enumerateThreads().map(t => t.id) : [threadId];

    if (threadIds.length === 0)
      throw new Error('failed to find any threads to trace');

    const traced = threadIds.filter(t => Traces.has(t));

    if (traced.length !== 0)
      throw new Error(`trace already exists for threadIds: ${traced}`);

    const trace = new CoverageTrace(threadIds, filename, modulePath);
    threadIds.forEach(t => Traces.set(t, trace));
    return trace;
  }

  protected doStop() {
    this.coverage.stop();
    this.trace.stop();
  }
}
