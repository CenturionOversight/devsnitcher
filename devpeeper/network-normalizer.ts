import type { NetworkEntry } from '../shared/types';

/**
 * Bounded, failure-focused normalization of the CDP `Network` domain events
 * that DEVPEEPER-004 observes:
 * `Network.requestWillBeSent`, `Network.responseReceived`,
 * `Network.loadingFinished` and `Network.loadingFailed`.
 *
 * The tracker reconstructs the minimum per-request state needed to emit the
 * existing DEVSnitch `NetworkEntry`. It retains only problem requests:
 * - an HTTP response with status `>= 400`; or
 * - a request Chromium reports as failed before a normal HTTP response (status `0`).
 *
 * Only browser-supplied fields are used. Nothing is invented: request identity
 * is Chrome's `requestId` (never URL matching), durations use one monotonic
 * Chromium clock, headers come from the request event, and status is preserved
 * verbatim (or `0` for a failed request). Response bodies are fetched only for
 * retained HTTP failures and are bounded.
 */

export const NETWORK_MAX_ENTRIES = 100;
export const RESPONSE_PREVIEW_MAX = 1000;
const TRUNCATION_SUFFIX = '…';

interface RequestHeaderMapLike {
  [key: string]: unknown;
}

export interface RequestWillBeSentParams {
  requestId?: string;
  request?: {
    url?: string;
    method?: string;
    headers?: RequestHeaderMapLike;
  };
  loaderId?: string;
  frameId?: number;
  timestamp?: number;
  wallTime?: number;
}

export interface ResponseReceivedParams {
  requestId?: string;
  response?: {
    status?: number;
  };
  frameId?: number;
  timestamp?: number;
}

export interface LoadingFinishedParams {
  requestId?: string;
  timestamp?: number;
}

export interface LoadingFailedParams {
  requestId?: string;
  timestamp?: number;
  errorText?: string;
}

export interface GetResponseBodyResult {
  body?: unknown;
  base64Encoded?: boolean;
}

interface PendingRequest {
  requestId: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  loaderId?: string;
  frameId?: number;
  startTimestamp?: number;
  endTimestamp?: number;
  status?: number;
  statusReceived: boolean;
  failed: boolean;
  errorText: string;
}

export interface NetworkFinalizeResult {
  entries: NetworkEntry[];
  needBody: string[];
}

export class NetworkTracker {
  private readonly pending = new Map<string, PendingRequest>();
  private readonly retained: NetworkEntry[] = [];
  private readonly retainedById = new Map<string, NetworkEntry>();
  private readonly retainedOrder: string[] = [];
  private readonly fetchedBodies = new Set<string>();

  onRequestWillBeSent(params: RequestWillBeSentParams): void {
    if (!params.requestId || typeof params.requestId !== 'string') return;
    if (this.pending.has(params.requestId)) return;

    this.pending.set(params.requestId, {
      requestId: params.requestId,
      url: params.request?.url ?? '',
      method: params.request?.method ?? 'GET',
      headers: normalizeHeaders(params.request?.headers),
      loaderId: params.loaderId,
      frameId: params.frameId,
      startTimestamp: typeof params.timestamp === 'number' ? params.timestamp : undefined,
      statusReceived: false,
      failed: false,
      errorText: '',
    });
  }

  onResponseReceived(params: ResponseReceivedParams): void {
    const pending = this.pending.get(params.requestId ?? '');
    if (!pending) return;
    pending.status = params.response?.status ?? 0;
    pending.statusReceived = true;
  }

  onLoadingFinished(params: LoadingFinishedParams): void {
    const pending = this.pending.get(params.requestId ?? '');
    if (!pending) return;
    if (typeof params.timestamp === 'number') pending.endTimestamp = params.timestamp;
    this.finalizeRequest(params.requestId ?? '');
  }

  onLoadingFailed(params: LoadingFailedParams): void {
    const pending = this.pending.get(params.requestId ?? '');
    if (!pending) return;
    if (typeof params.timestamp === 'number') pending.endTimestamp = params.timestamp;
    pending.failed = true;
    pending.errorText = params.errorText ?? '';
    this.finalizeRequest(params.requestId ?? '');
  }

  /** True when at least one problem request has been retained so far. */
  hasRetainedEntries(): boolean {
    return this.retained.length > 0;
  }

  /**
   * Finalizes requests that reached a conclusive state and returns retained
   * entries plus ids that need a body. Requests that have started but are still
   * awaiting an outcome (no `responseReceived`, no terminal event) are KEPT
   * pending so late `Network.*` lifecycle events can still update them. They
   * are purged by `clear()` on detach.
   * This prevents finalize from destroying in-flight requests that Chromium is
   * still delivering asynchronously (the acquisition-time network-loss defect).
   */
  finalize(): NetworkFinalizeResult {
    for (const id of [...this.pending.keys()]) {
      const pending = this.pending.get(id);
      // responseReceived makes the outcome known (retain if >=400); requests
      // without it stay pending for their terminal event or a later response.
      if (pending && pending.statusReceived) this.finalizeRequest(id);
    }

    const needBody: string[] = [];
    for (const id of this.retainedById.keys()) {
      const entry = this.retainedById.get(id);
      if (entry && entry.status >= 400 && !this.fetchedBodies.has(id)) needBody.push(id);
    }
    return { entries: this.retained.slice(), needBody };
  }

  /** Ids of started requests that have neither a response nor a terminal event. */
  undeterminedRequestIds(): string[] {
    const ids: string[] = [];
    for (const [id, pending] of this.pending) {
      if (!pending.statusReceived && !pending.failed) ids.push(id);
    }
    return ids;
  }

  getEntryForRequest(requestId: string): NetworkEntry | undefined {
    return this.retainedById.get(requestId);
  }

  markBodyFetched(requestId: string): void {
    this.fetchedBodies.add(requestId);
  }

  clear(): void {
    this.pending.clear();
    this.retained.length = 0;
    this.retainedById.clear();
    this.retainedOrder.length = 0;
    this.fetchedBodies.clear();
  }

  private finalizeRequest(requestId: string): void {
    const pending = this.pending.get(requestId);
    if (!pending) return;

    const entry = this.buildEntry(pending);
    if (entry) this.pushRetained(entry, requestId);
    this.pending.delete(requestId);
  }

  private buildEntry(pending: PendingRequest): NetworkEntry | null {
    if (pending.statusReceived && (pending.status ?? 0) >= 400) {
      return {
        url: pending.url,
        method: pending.method.toUpperCase(),
        status: pending.status ?? 0,
        duration: this.durationMs(pending),
        responsePreview: '',
        requestHeaders: pending.headers,
      };
    }
    if (pending.failed) {
      return {
        url: pending.url,
        method: pending.method.toUpperCase(),
        status: 0,
        duration: this.durationMs(pending),
        responsePreview: bound(pending.errorText),
        requestHeaders: pending.headers,
      };
    }
    return null;
  }

  private durationMs(pending: PendingRequest): number {
    // Use one monotonic Chromium clock for both ends. Do not mix wall-clock and
    // monotonic timestamps. Without a terminal monotonic timestamp, duration is 0.
    if (pending.startTimestamp != null && pending.endTimestamp != null) {
      return Math.max(0, Math.round((pending.endTimestamp - pending.startTimestamp) * 1000));
    }
    return 0;
  }

  private pushRetained(entry: NetworkEntry, requestId: string): void {
    if (this.retained.length >= NETWORK_MAX_ENTRIES) {
      const oldId = this.retainedOrder.shift();
      if (oldId) this.retainedById.delete(oldId);
      this.retained.shift();
    }
    this.retained.push(entry);
    this.retainedOrder.push(requestId);
    this.retainedById.set(requestId, entry);
  }
}

/**
 * Decodes the result of `Network.getResponseBody` into a bounded preview string.
 * Handles Chromium's `base64Encoded` flag. Missing/invalid bodies yield ''.
 */
export function decodeResponseBody(result: GetResponseBodyResult): string {
  if (typeof result?.body !== 'string') return '';
  const body = result.base64Encoded ? decodeBase64(result.body) : result.body;
  return bound(body);
}

function decodeBase64(value: string): string {
  try {
    return atob(value);
  } catch {
    return '';
  }
}

function normalizeHeaders(headers: RequestHeaderMapLike | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') out[key] = value;
    else if (value != null) out[key] = String(value);
  }
  return out;
}

function bound(value: string): string {
  if (!value) return '';
  return value.length <= RESPONSE_PREVIEW_MAX ? value : value.slice(0, RESPONSE_PREVIEW_MAX) + TRUNCATION_SUFFIX;
}
