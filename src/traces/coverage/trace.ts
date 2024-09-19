import { Output } from '../../io/output.js';
import { TraceBase, TraceData, Traces } from '../trace.js';
import { Coverage, CoverageSession } from './coverage.js';

class CoverageTraceData extends TraceData {
  private threadId: ThreadId;
  private filename: string;
  private file: File;
  private size: number = 0;

  public constructor(threadId: ThreadId, filename: string | null) {
    super();
    this.threadId = threadId;
    this.filename = filename ?? CoverageTraceData.getRandomFileName();
    this.file = new File(this.filename, 'wb+');
  }

  private static getRandomString(length: number): string {
    let output: string = '';
    const lookup = 'abcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
      const idx = Math.floor(Math.random() * lookup.length);
      const value = lookup[idx];
      output += value;
    }
    return output;
  }

  private static getRandomFileName(): string {
    const rand = CoverageTraceData.getRandomString(16);
    const filename = `/tmp/${rand}.cov`;
    return filename;
  }

  public append(events: ArrayBuffer) {
    this.file.write(events);
    this.size += events.byteLength;
  }

  public stop(): void {
    this.file.close();
  }

  public lines(): string[] {
    return [
      [
        'Wrote coverage for thread:',
        Output.yellow(this.threadId.toString()),
        'to:',
        Output.green(this.filename),
      ].join(' '),
    ];
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
    threadId: ThreadId,
    filename: string | null,
    modulePath: string | null,
  ) {
    const trace = new CoverageTraceData(threadId, filename);
    super(threadId, trace);

    let moduleFilter = Coverage.allModules;
    if (modulePath !== null) {
      moduleFilter = m => m.path === modulePath;
    }

    this.coverage = Coverage.start({
      moduleFilter: moduleFilter,
      onCoverage: coverageData => {
        this.trace.append(coverageData);
      },
      threadFilter: t => t.id === threadId,
    });
  }

  public static create(
    threadId: ThreadId,
    filename: string | null,
    modulePath: string | null,
  ): CoverageTrace {
    if (Traces.has(threadId)) {
      throw new Error(`trace already exists for threadId: ${threadId}`);
    }

    const trace = new CoverageTrace(threadId, filename, modulePath);
    Traces.set(threadId, trace);
    return trace;
  }

  protected doStop() {
    this.coverage.stop();
    this.trace.stop();
  }
}
