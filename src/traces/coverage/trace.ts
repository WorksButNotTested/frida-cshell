import { Output } from '../../io/output.js';
import { Trace, Traces } from '../trace.js';
import { Coverage, CoverageSession } from './coverage.js';

export class CoverageTrace implements Trace {
  private threadId: ThreadId;
  private filename: string;
  private file: File;
  private coverage: CoverageSession;
  private stopped: boolean = false;

  private constructor(threadId: ThreadId) {
    this.threadId = threadId;
    this.filename = CoverageTrace.getRandomFileName();
    this.file = new File(this.filename, 'wb+');
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

  public display() {
    Output.writeln(
      `Wrote coverage for thread: ${Output.yellow(this.threadId.toString())} to: ${Output.green(this.filename)}`,
    );
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
}
