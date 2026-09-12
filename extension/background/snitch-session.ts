import type { ConsoleEntry, DomContext, EnvironmentInfo, Evidence, JsErrorEntry, NetworkEntry, ScreenshotInfo } from '../../shared/types';
import { ChromiumObserver, type NetworkDrainOptions } from '../../devpeeper/chromium';
import type { DebuggerTransport } from '../../devpeeper/debugger-transport';

/**
 * DEVSnitcher SNITCH session — DevTools evidence snapshot on demand.
 *
 * DEVPEEPER does nothing until the user presses SNITCH. Pressing SNITCH binds to
 * the tab selected at that moment and acquires the diagnostic evidence DevTools
 * has available for it, then builds the SNITCHSHOT. There is no observation
 * window: acquisition finishes when the actual reads finish. `OBSERVING` means
 * "SNITCH acquisition is actively executing", never "waiting for future browser
 * events".
 *
 * Retrospective vs prospective CDP evidence:
 *   - environment / dom / selection: SNAPSHOT-capable. Acquired at SNITCH time
 *     by the bounded Chrome-mediated probe, reflecting the page's current state.
 *   - console / jsErrors / network: PROSPECTIVE ONLY. The Runtime/Network CDP
 *     domains do not replay history that occurred before the debugger attached;
 *     these surfaces reflect only what Chrome emits after attachment. An empty
 *     category therefore means "this API only observes events after
 *     attachment" — DEVSnitcher never fabricates retrospective evidence.
 *
 * The source tab is immutable: switching tabs never moves, restarts or
 * resurrects the session, and tab activation is never session authority.
 * Cancellation is terminal: it detaches the debugger and discards the unfinished
 * acquisition — including one still assembling evidence inside the bounded
 * network drain. There is at most one live session globally; it stays live (and
 * refusable/cancellable) until the report decision is made.
 *
 * This module is deliberately free of `chrome.*` so the lifecycle can be tested
 * against injected collaborators (transport, bounded probe, evidence hooks).
 */
export interface SnitchSessionContext {
  tabId: number;
  tabUrl: string;
  windowId?: number;
  userNotes: string;
  screenshot: boolean;
  screenshotInfo?: ScreenshotInfo;
}

/** The bounded contextual fields required by the report, from the snapshot probe. */
export interface SnitchBoundedContext {
  environment: EnvironmentInfo;
  dom: DomContext | null;
}

export interface SnitchSessionDeps {
  transport: () => DebuggerTransport;
  isSupported: (url: string) => boolean;
  /** Acquires environment + DOM for the session tab (browser-observed bounded probe). */
  acquireBounded(tabId: number): Promise<SnitchBoundedContext>;
  /**
   * Called once when the SNITCH acquisition is complete, with the assembled
   * evidence. The coordinator redacts, builds the report and fills the private
   * SNITCHSHOT buffer here. The debugger detaches afterward.
   */
  onComplete(evidence: Evidence, ctx: SnitchSessionContext): Promise<void>;
  /** Called on CANCEL / removal after the debugger detaches. Best-effort. */
  onCancel?(ctx: SnitchSessionContext): void | Promise<void>;
  /** Optional ChromiumObserver tuning (bounded network drain), injectable in tests. */
  networkDrain?: NetworkDrainOptions;
}

/**
 * A live SNITCH session: the attached observer, the immutable session context,
 * and the cancellation latch. The record stays installed through evidence
 * assembly (the bounded network drain can run up to its hard deadline), so the
 * manager keeps reporting "acquiring" and a concurrent cancel remains effective
 * until the report decision is made.
 */
interface LiveSnitchSession {
  observer: ChromiumObserver;
  ctx: SnitchSessionContext;
  /**
   * Latched by `cancel()`. A cancel that arrives while the acquisition is still
   * winding down is terminal: the reads may finish, but the evidence is
   * discarded and `onComplete` is never invoked for a canceled session.
   */
  canceled: boolean;
}

export class SnitchSessionManager {
  private session: LiveSnitchSession | null = null;
  private bounded: SnitchBoundedContext | null = null;
  private lastError: string | null = null;

  constructor(private readonly deps: SnitchSessionDeps) {}

  /** True while a SNITCH acquisition is actively running or assembling. */
  isObserving(): boolean {
    return this.session?.observer.isRunning() ?? false;
  }

  /** The immutable tab id currently bound, or undefined when idle. */
  attachedTabId(): number | undefined {
    return this.session?.observer.attachedTabId;
  }

  /** Last session error (non-fatal status detail), or null. */
  getLastError(): string | null {
    return this.lastError;
  }

  /**
   * Runs a SNITCH acquisition on `ctx`'s tab and finishes when the reads
   * finish: attaches the single Chromium observer, snapshots the bounded page
   * context, assembles the available evidence, then finalizes. Resolves `true`
   * when the acquisition ran; `false` when one is already live (global active
   * gate). Throws when startup fails (e.g. unsupported tab or debugger attach
   * error); the caller reports the error and returns to idle.
   */
  async start(ctx: SnitchSessionContext): Promise<boolean> {
    if (this.session) return false;
    if (!ctx.tabId || !this.deps.isSupported(ctx.tabUrl)) {
      throw new Error('DEVSnitcher cannot inspect this tab.');
    }

    const observer = new ChromiumObserver(ctx.tabId, this.deps.transport(), {
      networkDrain: this.deps.networkDrain,
    });
    await observer.start();
    this.session = { observer, ctx, canceled: false };
    this.bounded = null;
    this.lastError = null;

    // SNITCH-time acquisition: snapshot the current page context while the
    // observer is attached, then finalize as soon as the reads complete. No
    // six-second (or any) harvest wait; an empty console/jsErrors/network result
    // is legitimate and complete.
    try {
      this.bounded = await this.deps.acquireBounded(ctx.tabId);
    } catch {
      this.bounded = null;
    }

    await this.complete();
    return true;
  }

  /**
   * Runs finalization of the current session once acquisition reads are done.
   * Public so deterministic tests can confirm completion is driven by the reads,
   * not by a timer.
   */
  async complete(): Promise<void> {
    const session = this.session;
    if (!session) return;
    try {
      await this.finalize(session);
    } catch (err) {
      this.lastError = err instanceof Error ? err.message : String(err);
      await this.teardown(session).catch(() => undefined);
    }
  }

  /**
   * Cancellation is terminal: detaches the debugger, discards the unfinished
   * acquisition and clears all live state. Resolves `true` when a live session
   * was canceled, `false` when there was nothing to cancel.
   */
  async cancel(): Promise<boolean> {
    const session = this.session;
    if (!session) return false;

    // Clear live state synchronously so no later activation can resurrect it,
    // and latch the cancellation: an acquisition still winding down inside the
    // bounded network drain must discard its evidence instead of storing it.
    session.canceled = true;
    this.session = null;

    // Stopping the observer clears its network tracker, which collapses the
    // in-flight drain (undetermined becomes empty) so the reads finish fast.
    await session.observer.stop().catch(() => undefined);
    if (!this.session) this.bounded = null;
    if (this.deps.onCancel) {
      await Promise.resolve(this.deps.onCancel(session.ctx)).catch(() => undefined);
    }
    return true;
  }

  /** Detach the live session when its source tab is removed (no migration). */
  async handleRemoved(tabId: number): Promise<void> {
    if (this.session?.observer.attachedTabId === tabId) {
      await this.cancel();
    }
  }

  private async finalize(session: LiveSnitchSession): Promise<void> {
    try {
      // A cancel that raced the reads is terminal: discard the evidence and
      // never invoke onComplete for a canceled session.
      if (session.canceled) return;

      const environment = this.bounded?.environment;

      if (!environment) {
        // The bounded page context failed to acquire; this cannot satisfy the
        // report contract, so fail the session and detach without a report.
        this.lastError = 'DEVPEEPER could not acquire the bounded page context.';
        return;
      }

      // The session stays live through assembly: getNetworkEntries' bounded
      // network drain can run up to its hard deadline, and during that window
      // isObserving() must hold and cancel/handleRemoved must remain effective.
      const evidence = await this.assembleEvidence(
        session.observer,
        environment,
        session.ctx,
      );
      if (session.canceled) return;

      // Clear live state before the coordinator stores the report so a cancel
      // during the store sees an idle manager (it cannot unstore a report).
      this.session = null;
      await this.deps.onComplete(evidence, session.ctx);
    } catch (err) {
      this.lastError = err instanceof Error ? err.message : String(err);
    } finally {
      // Always detach once the report has been attempted/discarded; the debugger
      // must not remain attached after the session resolves, succeed or not.
      await this.teardown(session);
    }
  }

  private async teardown(session: LiveSnitchSession): Promise<void> {
    // Only the session that still owns live state may clear it: a canceled or
    // superseded session winding down must never clobber a newer session.
    if (this.session === session) this.session = null;
    await session.observer.stop().catch(() => undefined);
    if (!this.session) this.bounded = null;
  }

  private async assembleEvidence(
    observer: ChromiumObserver,
    environment: EnvironmentInfo,
    ctx: SnitchSessionContext,
  ): Promise<Evidence> {
    const console: ConsoleEntry[] = observer.getConsoleEntries();
    const jsErrors: JsErrorEntry[] = observer.getJsErrorEntries();
    const network: NetworkEntry[] = await observer.getNetworkEntries();
    const dom = this.bounded?.dom ?? null;
    return {
      environment,
      console,
      jsErrors,
      network,
      dom,
      screenshot: ctx.screenshotInfo ?? null,
    };
  }
}