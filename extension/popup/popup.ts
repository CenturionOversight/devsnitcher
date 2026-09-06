import type { SnitchMessage } from '../../shared/types';
import { fingerprint } from '../../report/clipboard';
import { releaseReport, sendReleased } from './release';
import { ctaConfig, type PopupCtaState } from './cta-config';

const STATUS_POLL_MS = 500;

// Pre-fetched report content, held in popup memory so COPY can write to the OS
// clipboard within the click gesture. The private buffer in the background
// remains authoritative and is only cleared on a confirmed CLIPBOARD_CLEARED.
let cachedReport: string | null = null;
// The in-flight prefetch, so COPY never issues a duplicate read and never
// falsely behaves as though a synchronous report is ready before it is.
let cachePromise: Promise<string | null> | null = null;

document.addEventListener('DOMContentLoaded', () => {
  const snitchBtn = document.getElementById('snitch') as HTMLButtonElement;
  const closeBtn = document.getElementById('close') as HTMLButtonElement;
  const copyBtn = document.getElementById('copy') as HTMLButtonElement;
  const notes = document.getElementById('notes') as HTMLTextAreaElement;
  const screenshotCb = document.getElementById('screenshot') as HTMLInputElement;
  const field = document.querySelector('.field') as HTMLElement | null;
  const screenshotRow = document.querySelector('.checkbox') as HTMLElement | null;
  const snitchStateEl = document.getElementById('snitch-state') as HTMLSpanElement;
  const copyStateEl = document.getElementById('copy-state') as HTMLSpanElement;
  const resultEl = document.getElementById('result') as HTMLParagraphElement;

  let pollTimer: number | null = null;
  // The authoritative lifecycle (background states + the popup-local COPYING).
  let currentState: PopupCtaState = 'idle';

  async function send(msg: SnitchMessage): Promise<SnitchMessage | undefined> {
    return (await chrome.runtime.sendMessage(msg)) as SnitchMessage | undefined;
  }

  /**
   * The single deterministic projection of the lifecycle onto the three CTAs.
   * All three remain rendered; the state decides which is enabled and what each
   * contextual label says. This is the only place CTA configuration is derived,
   * so the popup can never present contradictory active actions.
   */
  function render(state: PopupCtaState): void {
    currentState = state;
    const cfg = ctaConfig(state);

    snitchBtn.disabled = !cfg.snitchEnabled;
    closeBtn.hidden = !cfg.closeVisible;
    copyBtn.disabled = !cfg.copyEnabled;

    snitchStateEl.textContent = cfg.snitchLabel;
    copyStateEl.textContent = cfg.copyLabel;

    if (field) field.hidden = !cfg.inputsEnabled;
    if (screenshotRow) screenshotRow.hidden = !cfg.inputsEnabled;
    notes.disabled = !cfg.inputsEnabled;
    screenshotCb.disabled = !cfg.inputsEnabled;

    // Drive the helper message from the same projection; no divergent UI bits.
    if (state === 'observing') {
      resultEl.textContent = 'Collecting browser evidence on the selected tab…';
      resultEl.className = 'result';
    } else if (state === 'snitchshot_pending') {
      resultEl.textContent = 'SNITCHSHOT ready. Copy it, then Ctrl+V anywhere.';
      resultEl.className = 'result';
    } else if (state === 'copying') {
      // copy button sub-label shows "Copying…"; keep a neutral helper line.
      resultEl.textContent = '';
      resultEl.className = 'result';
    } else {
      resultEl.textContent = '';
      resultEl.className = 'result';
    }
  }

  async function refreshStatus(fromPoll = false): Promise<void> {
    // Ignore a stale poll if a local COPYING transition is in progress — the
    // background, which may not know about COPYING yet, must not clobber it.
    if (currentState === 'copying') return;

    const response = await send({ type: 'GET_STATUS' } satisfies SnitchMessage);
    if (!response) return;

    if (response.type === 'STATUS_RESULT') {
      render(response.state);
      if (response.state === 'observing') {
        schedulePoll();
      } else if (response.state === 'snitchshot_pending') {
        stopPoll();
        // Pre-fetch the report ahead of the gesture so the COPY click writes
        // from a report already held in popup memory.
        void fetchReportForCache();
      } else {
        // idle (or unknown): stop polling and drop any stale cached report.
        stopPoll();
        cachedReport = null;
        cachePromise = null;
        if (fromPoll) {
          resultEl.textContent = '';
          resultEl.className = 'result';
        }
      }
    } else if (response.type === 'EVIDENCE_ERROR') {
      stopPoll();
      cachedReport = null;
      cachePromise = null;
      render('idle');
      resultEl.textContent = response.error;
      resultEl.className = 'result err';
    }
  }

  function schedulePoll(): void {
    if (pollTimer != null) return;
    pollTimer = window.setInterval(() => void refreshStatus(true), STATUS_POLL_MS);
  }

  function stopPoll(): void {
    if (pollTimer != null) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function showError(message: string): void {
    resultEl.textContent = message;
    resultEl.className = 'result err';
  }

  // Fetch the pending report into popup memory. Runs off the gesture path (from
  // status polling / initial render) so the COPY click writes from an already-
  // cached report instead of awaiting a cross-process read mid-gesture. The
  // in-flight promise is tracked so COPY waits on exactly this fetch.
  async function fetchReportForCache(): Promise<string | null> {
    if (cachePromise) return cachePromise;
    cachePromise = (async () => {
      try {
        const content = await send({ type: 'GET_SNITCHSHOT' } satisfies SnitchMessage);
        if (!content) return null;
        if (content.type !== 'SNITCHSHOT_CONTENT') return null;
        cachedReport = content.report;
        // Boundary E — popup cache. Must match A/B/C/D's fingerprint.
        console.log(`[popup] received ${fingerprint(content.report)}`);
        return content.report;
      } catch (err) {
        console.log(
          `[popup] received FAILED: ${err instanceof Error ? err.message : String(err)}`,
        );
        return null;
      }
    })();
    return cachePromise;
  }

  snitchBtn.addEventListener('click', async () => {
    snitchBtn.disabled = true;
    resultEl.textContent = 'Starting…';
    resultEl.className = 'result';

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'SNITCH',
        userNotes: notes.value.trim(),
        screenshot: screenshotCb.checked,
      } satisfies SnitchMessage);

      if (!response) throw new Error('No response from background');

      if (response.type === 'SNITCH_ERROR') {
        showError(response.error);
      } else if (response.type === 'SNITCH_ACCEPTED') {
        // SNITCH accepted; the project has entered OBSERVING. Let status drive UI.
      } else {
        showError('Unexpected response from background.');
      }
      await refreshStatus();
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Unknown error');
      await refreshStatus();
    } finally {
      snitchBtn.disabled = false;
    }
  });

  closeBtn.addEventListener('click', async () => {
    closeBtn.disabled = true;
    resultEl.textContent = 'Cancelling…';
    resultEl.className = 'result';

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'CANCEL_SNITCH',
      } satisfies SnitchMessage);
      if (!response) throw new Error('No response from background');
      if (response.type === 'EVIDENCE_ERROR') {
        showError(response.error);
      } else {
        stopPoll();
        cachedReport = null;
        cachePromise = null;
        // Cancel returns authoritative state to IDLE; the backend confirms it.
        await refreshStatus();
      }
    } catch (err) {
      showError(err instanceof Error ? err.message : 'Unknown error');
      await refreshStatus();
    } finally {
      closeBtn.disabled = false;
    }
  });

  copyBtn.addEventListener('click', async () => {
    // Popup-local COPYING transition. No other CTA is actionable here, and the
    // button shows progress until the release is confirmed.
    render('copying');

    try {
      // Write the report already fetched into popup memory when the session
      // completed. COPY waits on the in-flight prefetch (never issues a
      // duplicate read) and never writes from an empty/stale cache — if there
      // is no cached report the release cannot proceed and the SNITCHSHOT stays
      // pending.
      let report = cachedReport;
      if (!report && cachePromise) {
        report = await cachePromise;
        cachedReport = report;
      }
      if (!report) {
        throw new Error('The report is not ready to copy. Wait for SNITCHSHOT_PENDING, then press COPY again.');
      }

      const outcome = await releaseReport(report, () =>
        sendReleased(() => send({ type: 'CLIPBOARD_RELEASED' } satisfies SnitchMessage)),
      );
      if (outcome !== 'released') {
        throw new Error('The SNITCHSHOT could not be released; it is still pending.');
      }

      cachedReport = null;
      cachePromise = null;
      // Release confirmed: the private buffer is cleared and the report is on
      // the clipboard. Return to authoritative IDLE.
      await refreshStatus();
      resultEl.textContent = 'Report on clipboard. Now press Ctrl+V anywhere.';
      resultEl.className = 'result ok';
      // A short confirmation may remain visible without creating a durable state.
      snitchStateEl.textContent = 'Copied ✓';
    } catch (err) {
      // The buffer is retained; stay in the authoritative pending state so COPY
      // can be retried. The background still reports snitchshot_pending.
      await refreshStatus();
      showError(err instanceof Error ? err.message : 'Copy failed');
    }
  });

  void refreshStatus();
});