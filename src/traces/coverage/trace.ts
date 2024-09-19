import { Output } from '../../io/output.js';
import { Trace, TraceData, Traces } from '../trace.js';
import { Coverage, CoverageSession } from './coverage.js';

class CoverageTraceData implements TraceData {
  private filename: string;
  private threadId: ThreadId;

  public constructor(threadId: ThreadId, filename: string) {
    this.threadId = threadId;
    this.filename = filename;
  }

  public display() {
    Output.writeln(
      `Wrote coverage for thread: ${Output.yellow(this.threadId.toString())} to: ${Output.green(this.filename)}`,
    );
  }
}
export class CoverageTrace implements Trace {
  private file: File;
  private coverage: CoverageSession;
  private stopped: boolean = false;
  private trace: CoverageTraceData;

  private constructor(threadId: ThreadId) {
    const filename = CoverageTrace.getRandomFileName();
    this.trace = new CoverageTraceData(threadId, filename);

    this.file = new File(filename, 'wb+');
    this.coverage = Coverage.start({
      moduleFilter: m => Coverage.allModules(m),
      onCoverage: coverageData => {
        this.file.write(coverageData);
      },
      threadFilter: t => t.id === threadId,
    });
  }

  public static create(threadId: ThreadId): CoverageTrace {
    if (Traces.has(threadId)) {
      throw new Error(`trace already exists for threadId: ${threadId}`);
    }

    const trace = new CoverageTrace(threadId);
    Traces.set(threadId, trace);
    return trace;
  }

  public stop() {
    if (this.stopped) return;
    this.coverage.stop();
    this.file.close();
    this.stopped = true;
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
    const rand = CoverageTrace.getRandomString(16);
    const filename = `/tmp/${rand}.cov`;
    return filename;
  }

  public data(): CoverageTraceData {
    return this.trace;
  }
}
