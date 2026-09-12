import { test, describe } from 'node:test';
import * as assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><head><title>TestPage</title></head><body></body></html>', {
  url: 'https://example.com/test-page',
  pretendToBeVisual: true,
  runScripts: 'dangerously',
});

const { window } = dom;

function setGlobal(name: string, value: unknown): void {
  Object.defineProperty(globalThis as any, name, {
    value,
    writable: true,
    configurable: true,
  });
}

// Install browser globals from jsdom where available, fall back to Node built-ins
setGlobal('window', window);
setGlobal('document', window.document);
setGlobal('navigator', window.navigator);
setGlobal('console', window.console);
setGlobal('performance', globalThis.performance);
setGlobal('customElements', window.customElements);
setGlobal('XMLHttpRequest', window.XMLHttpRequest);
// Use Node's built-in Request/Response/fetch if jsdom doesn't provide them
const ReqCtor = (window as any).Request || globalThis.Request;
const RespCtor = (window as any).Response || globalThis.Response;
setGlobal('Request', ReqCtor);
setGlobal('Headers', (window as any).Headers || globalThis.Headers);
setGlobal('Response', RespCtor);
setGlobal('Element', window.Element);
setGlobal('HTMLInputElement', window.HTMLInputElement);
setGlobal('HTMLTextAreaElement', window.HTMLTextAreaElement);
setGlobal('InputEvent', (window as any).InputEvent || window.Event);
setGlobal('location', window.location);
setGlobal('ErrorEvent', window.ErrorEvent);
setGlobal('PromiseRejectionEvent', window.PromiseRejectionEvent);
setGlobal('Event', window.Event);

// Mock chrome API for screenshot — accepts both (windowId, opts, cb) and (opts, cb)
setGlobal('chrome', {
  tabs: {
    captureVisibleTab: (...args: unknown[]) => {
      const cb = args[args.length - 1];
      if (typeof cb === 'function') (cb as (d: string) => void)('data:image/png;base64,iVBORw0KGgo=');
    },
  },
  runtime: {},
} as any);

// Mock createImageBitmap for screenshot dimension decoding
setGlobal(
  'createImageBitmap',
  (async () => ({
    width: 1280,
    height: 720,
    close() {},
  })) as any,
);

// Now import collectors and report modules
import { captureScreenshot } from '../collectors/screenshot';
import {
  redactEvidence,
  redactCookieString,
  redactConsoleEntry,
  redactJsErrorEntry,
  redactDomContext,
  redactUrl,
} from '../redaction/index';
import { buildMarkdownReport } from '../report/markdown';
import { buildJsonReport } from '../report/json';
import { writeToClipboard, writeTextViaDomCopy, fingerprint } from '../report/clipboard';
import { releaseReport, sendReleased } from '../extension/popup/release';
import { ctaConfig } from '../extension/popup/cta-config';
import { SnitchshotBuffer, SNITCHSHOT_BUFFER_KEY } from '../extension/background/snitchshot-buffer';
import type { SnitchshotStorageLike } from '../extension/background/snitchshot-buffer';
import { SnitchSessionManager } from '../extension/background/snitch-session';
import type { SnitchSessionContext } from '../extension/background/snitch-session';
import { snapshotProbe, type BoundedSnapshot } from '../devpeeper/snapshot-probe';
import {
  makeBoundedObservation,
  normalizeBoundedSnapshot,
  type InjectionResultLike,
} from '../devpeeper/observation';
import { ChromiumObserver, type NetworkDrainOptions } from '../devpeeper/chromium';
import { NetworkTracker } from '../devpeeper/network-normalizer';
import type { DebuggerTarget, DebuggerTransport } from '../devpeeper/debugger-transport';
import { normalizeConsoleApi, normalizeExceptionThrown } from '../devpeeper/runtime-normalizer';
import type { Evidence } from '../shared/types';

describe('DEVSnitcher collectors', () => {
  describe('screenshot', () => {
    test('returns data URL from chrome.tabs.captureVisibleTab', async () => {
      const result = await captureScreenshot();
      assert.ok(result);
      assert.ok(result?.dataUrl.startsWith('data:image/'));
    });

    test('populates width and height from decoded image', async () => {
      const result = await captureScreenshot();
      assert.ok(result);
      assert.equal(result?.width, 1280);
      assert.equal(result?.height, 720);
    });
  });
});

describe('redaction', () => {
  const evidence: Evidence = {
    environment: {
      url: 'https://example.com',
      title: 'Test',
      browser: 'Chrome',
      platform: 'Win32',
      viewport: { width: 1280, height: 720 },
      timestamp: 0,
    },
    console: [
      { level: 'error', message: 'Auth failed: password=secret123 token=bearer_abc', timestamp: 100 },
    ],
    network: [
      {
        url: 'https://api.example.com/data?token=sk-1234567890abcdef',
        method: 'GET',
        status: 401,
        duration: 42,
        responsePreview: '{"error": "Unauthorized", "Authorization": "Bearer xyz789"}',
        requestHeaders: {
          Authorization: 'Bearer abc123',
          'X-API-Key': 'key_99999',
          Cookie: 'session=abc123; jwt=eyJhbGc',
          Accept: 'application/json',
        },
      },
    ],
    jsErrors: [
      {
        type: 'unhandled_exception',
        message: 'Bearer abc123 token here',
        stack: 'at foo (api.js:1:1)',
      },
    ],
    dom: {
      selector: '#test',
      html: '<div>password=pwd123</div>',
      className: '',
      tagName: 'div',
      isFocused: false,
    },
    screenshot: null,
  };

  test('redacts authorization headers, bearer tokens, API keys, cookies', () => {
    const redacted = redactEvidence(evidence);
    const headers = redacted.network[0].requestHeaders;
    assert.equal(headers.Authorization, '[REDACTED]');
    assert.equal(headers['X-API-Key'], '[REDACTED]');
    assert.equal(headers.Cookie, '[REDACTED]');
    assert.equal(headers.Accept, 'application/json');
  });

  test('redacts sensitive query params in URL', () => {
    const redacted = redactEvidence(evidence);
    assert.ok(!redacted.network[0].url.includes('sk-1234567890abcdef'));
    assert.ok(redacted.network[0].url.includes('[REDACTED]'));
  });

  test('redacts bearer tokens in response preview', () => {
    const redacted = redactEvidence(evidence);
    assert.ok(!redacted.network[0].responsePreview.includes('xyz789'));
  });

  test('redacts secrets in console messages and DOM html', () => {
    const redacted = redactEvidence(evidence);
    assert.ok(!redacted.console[0].message.includes('secret123'));
    assert.ok(!redacted.dom!.html.includes('pwd123'));
  });

  test('does not redact non-sensitive data', () => {
    const safe: Evidence = {
      environment: {
      url: 'https://example.com',
      title: 'Test',
      browser: 'Chrome',
      platform: 'Win32',
      viewport: { width: 1280, height: 720 },
      timestamp: 0,
    },
      console: [{ level: 'log', message: 'User clicked button', timestamp: 100 }],
      network: [
        {
          url: 'https://api.example.com/users?page=2',
          method: 'GET',
          status: 200,
          duration: 10,
          responsePreview: '{"id": 1, "name": "Alice"}',
          requestHeaders: { Accept: 'application/json' },
        },
      ],
      jsErrors: [],
      dom: null,
      screenshot: null,
    };
    const redacted = redactEvidence(safe);
    assert.equal(redacted.console[0].message, 'User clicked button');
    assert.equal(redacted.network[0].url, 'https://api.example.com/users?page=2');
    assert.equal(redacted.network[0].responsePreview, '{"id": 1, "name": "Alice"}');
  });

  test('redacts bearer tokens and URL query tokens in stack traces', () => {
    const redacted = redactEvidence({
      ...evidence,
      console: [
        {
          level: 'error',
          message: 'boom',
          timestamp: 100,
          stack: 'Error: boom\n    at fetch (https://api.example.com/data?token=sk-1234567890abcdef:10:5)\n    at getData (app.js:20:10)',
        },
      ],
      jsErrors: [
        {
          type: 'unhandled_exception' as const,
          message: 'boom',
          stack: 'Error: boom\n    at api (https://api.example.com/auth?access_token=abc123secret:1:1)',
        },
      ],
    });

    assert.ok(redacted.console[0].stack);
    assert.ok(!redacted.console[0].stack!.includes('sk-1234567890abcdef'));
    assert.ok(!redacted.jsErrors[0].stack!.includes('abc123secret'));
    assert.ok(redacted.console[0].stack!.includes('[REDACTED]'));
    assert.ok(redacted.jsErrors[0].stack!.includes('[REDACTED]'));
  });

  test('redacts tokens inside URLs embedded in response previews', () => {
    const redacted = redactEvidence({
      ...evidence,
      network: [
        {
          ...evidence.network[0],
          responsePreview:
            '{"url": "https://api.example.com/data?token=sk-secret789", "msg": "ok"}',
        },
      ],
    });

    assert.ok(!redacted.network[0].responsePreview.includes('sk-secret789'));
    assert.ok(redacted.network[0].responsePreview.includes('[REDACTED]'));
  });

  test('redactCookieString redacts sensitive cookies but keeps benign ones', () => {
    const result = redactCookieString('session=abc123; theme=dark; jwt=eyJhbGc; lang=en');
    assert.ok(result.includes('session=[REDACTED]'));
    assert.ok(result.includes('jwt=[REDACTED]'));
    assert.ok(result.includes('theme=dark'));
    assert.ok(result.includes('lang=en'));
  });

  test('console, DOM HTML and JS error messages redact URL query secrets (BUG 3)', () => {
    const consoleEntry = redactConsoleEntry({
      level: 'log',
      message: 'GET https://api.example.com/data?token=secret123',
      timestamp: 1,
    });
    assert.ok(consoleEntry.message.includes('token=[REDACTED]'));
    assert.ok(!consoleEntry.message.includes('secret123'));

    const dom = redactDomContext({
      selector: 'div',
      tagName: 'DIV',
      className: 'x',
      isFocused: false,
      html: '<a href="https://api.example.com/x?access_token=abc123">go</a>',
    });
    assert.ok(dom.html.includes('access_token=[REDACTED]'));
    assert.ok(!dom.html.includes('abc123'));

    const jsError = redactJsErrorEntry({
      type: 'unhandled_exception',
      message: 'failed to load https://api.example.com/y?password=hunter2',
      stack: 'at fn (https://api.example.com/z?code=qwerty)',
    });
    assert.ok(jsError.message.includes('password=[REDACTED]'));
    assert.ok(!jsError.message.includes('hunter2'));
    assert.ok(jsError.stack.includes('code=[REDACTED]'));
    assert.ok(!jsError.stack.includes('qwerty'));
  });

  test('sensitive fragment parameters are redacted, safe fragments preserved (BUG 4)', () => {
    assert.equal(
      redactUrl('https://x.test/path#access_token=secret').url,
      'https://x.test/path#access_token=[REDACTED]',
    );
    assert.equal(
      redactUrl('https://x.test/path#token=abc&state=xyz').url,
      'https://x.test/path#token=[REDACTED]&state=xyz',
    );
    assert.equal(
      redactUrl('https://x.test/path#foo=bar&sid=1').url,
      'https://x.test/path#foo=bar&sid=[REDACTED]',
    );
    assert.equal(
      redactUrl('https://x.test/path#section-name').url,
      'https://x.test/path#section-name',
    );
    assert.equal(
      redactUrl('https://x.test/path?a=1#token=zzz').url,
      'https://x.test/path?a=1#token=[REDACTED]',
    );
    assert.equal(
      redactUrl('https://x.test/path#plain=value').url,
      'https://x.test/path#plain=value',
    );
  });

  test('fragment redaction preserves encoded safe values byte-for-byte (BUG A)', () => {
    // Percent-encoding of non-sensitive fragment values is never de-encoded.
    assert.equal(
      redactUrl('https://x.test/path#token=z&continue=https%3A%2F%2Fevil.com').url,
      'https://x.test/path#token=[REDACTED]&continue=https%3A%2F%2Fevil.com',
    );
    // %26 inside a value must not be re-interpreted as a parameter separator.
    assert.equal(
      redactUrl('https://x.test/path#foo=a%26b&token=z').url,
      'https://x.test/path#foo=a%26b&token=[REDACTED]',
    );
    // %20 inside a value must remain encoded.
    assert.equal(
      redactUrl('https://x.test/path#msg=hello%20world&sid=9').url,
      'https://x.test/path#msg=hello%20world&sid=[REDACTED]',
    );
    // Mixed sensitive/non-sensitive params: safe values untouched, in order.
    assert.equal(
      redactUrl('https://x.test/path#state=xyz&next=c%26b&code=z&q=1%202').url,
      'https://x.test/path#state=xyz&next=c%26b&code=[REDACTED]&q=1%202',
    );
    // Ordinary anchors (no `=`) remain unchanged even alongside sensitive params.
    assert.equal(
      redactUrl('https://x.test/path#features.top=1&section-name&token=z').url,
      'https://x.test/path#features.top=1&section-name&token=[REDACTED]',
    );
  });

  test('query redaction preserves encoded safe values without double-encoding (BUG B)', () => {
    // Encoded redirect URL remains byte-for-byte unchanged when a neighbor redacts.
    assert.equal(
      redactUrl('https://x.test/path?redirect=https%3A%2F%2Fevil.com&token=z').url,
      'https://x.test/path?redirect=https%3A%2F%2Fevil.com&token=[REDACTED]',
    );
    // %26 and %20 stay encoded, not re-encoded or decoded.
    assert.equal(
      redactUrl('https://x.test/path?x=%26y&msg=a%20b&token=z').url,
      'https://x.test/path?x=%26y&msg=a%20b&token=[REDACTED]',
    );
    // Duplicate safe params remain present and ordered.
    assert.equal(
      redactUrl('https://x.test/path?a=1&a=2&token=z').url,
      'https://x.test/path?a=1&a=2&token=[REDACTED]',
    );
    // A query with no fragment must not gain a trailing `#`.
    assert.equal(
      redactUrl('https://x.test/path?token=z').url,
      'https://x.test/path?token=[REDACTED]',
    );
    // Sensitive values are redacted.
    assert.equal(
      redactUrl('https://api.example.com/data?token=sk-1234567890abcdef').url,
      'https://api.example.com/data?token=[REDACTED]',
    );
  });
});

describe('report builder', () => {
  test('markdown report has all required sections and redaction', () => {
    const evidence: Evidence = {
      environment: {
        url: 'https://example.com/test-page',
        title: 'Test',
        browser: 'Chrome',
        platform: 'Win32',
        viewport: { width: 1280, height: 720 },
        timestamp: 0,
      },
      console: [{ level: 'error', message: 'DEVSnitcher test: console error', timestamp: 100 }],
      network: [
        {
          url: 'https://api.example.com/missing',
          method: 'GET',
          status: 404,
          duration: 50,
          responsePreview: 'Not Found',
          requestHeaders: { Authorization: 'Bearer abc123' },
        },
      ],
      jsErrors: [
        {
          type: 'unhandled_exception',
          message: 'DEVSnitcher test: unhandled exception',
          stack: '',
        },
      ],
      dom: {
        selector: '#test',
        html: '<div>Test</div>',
        className: 'test',
        tagName: 'div',
        isFocused: false,
      },
      screenshot: { dataUrl: 'data:image/png;base64,abc', width: 100, height: 100 },
    };

    const redacted = redactEvidence(evidence);
    const report = buildMarkdownReport({
      evidence: redacted,
      userNotes: 'Clicked Save. Nothing happened.',
    });

    assert.ok(report.includes('# DEVSNITCHER REPORT'));
    assert.ok(report.includes('## User Description'));
    assert.ok(report.includes('Clicked Save. Nothing happened.'));
    assert.ok(report.includes('## Environment'));
    assert.ok(report.includes('https://example.com/test-page'));
    assert.ok(report.includes('## Console'));
    assert.ok(report.includes('console error'));
    assert.ok(report.includes('## Network'));
    assert.ok(report.includes('api.example.com/missing'));
    assert.ok(report.includes('404'));
    assert.ok(report.includes('## JavaScript'));
    assert.ok(report.includes('unhandled exception'));
    assert.ok(report.includes('## DOM Context'));
    assert.ok(report.includes('#test'));
    assert.ok(report.includes('## Screenshot'));
    assert.ok(report.includes('Attached'));
    assert.ok(report.includes('## Summary'));
    // Redaction in report
    assert.ok(!report.includes('Bearer abc123'));
    assert.ok(report.includes('[REDACTED]'));
  });

  test('JSON report has correct schema and structure', () => {
    const evidence: Evidence = {
      environment: {
        url: 'https://example.com',
        title: 'Test',
        browser: 'Chrome',
        platform: 'Win32',
        viewport: { width: 1280, height: 720 },
        timestamp: 0,
      },
      console: [{ level: 'error', message: 'fail', timestamp: 100 }],
      network: [
        {
          url: 'https://x.com',
          method: 'GET',
          status: 0,
          duration: 1,
          responsePreview: '',
          requestHeaders: {},
        },
      ],
      jsErrors: [{ type: 'promise_rejection', message: 'oops', stack: '' }],
      dom: null,
      screenshot: null,
    };
    const report = buildJsonReport({ evidence, userNotes: 'Test' });
    const parsed = JSON.parse(report);
    assert.equal(parsed.schema, 'devsnitcher/v1');
    assert.equal(parsed.userDescription, 'Test');
    assert.ok(parsed.evidence);
    assert.ok(parsed.summary);
    assert.equal(parsed.summary.failedRequests, 1);
    assert.equal(parsed.summary.unhandledErrors, 1);
  });
});

describe('DEVPEEPER Chrome-mediated bounded observation', () => {
  test('bounded probe returns plain serializable data without a postMessage transport', () => {
    const source = snapshotProbe.toString();
    assert.ok(!source.includes('postMessage'), 'probe must not use window.postMessage');

    const snapshot = snapshotProbe();
    assert.ok(snapshot.environment);
    assert.equal(typeof snapshot.environment.url, 'string');
    assert.equal(typeof snapshot.environment.title, 'string');
    assert.equal(typeof snapshot.environment.browser, 'string');
    assert.equal(typeof snapshot.environment.platform, 'string');
    assert.equal(typeof snapshot.environment.viewport.width, 'number');
    assert.equal(typeof snapshot.environment.viewport.height, 'number');

    // Round-trips through JSON, so Chrome can serialize it back to the extension.
    const serialized = JSON.parse(JSON.stringify(snapshot)) as BoundedSnapshot;
    assert.deepEqual(serialized, snapshot);
  });

  test('Chrome-mediated snapshot normalizes into EnvironmentInfo and DomContext', () => {
    const snapshot: BoundedSnapshot = {
      environment: {
        url: 'https://example.com/page',
        title: 'Page',
        browser: 'Chrome',
        platform: 'Win32',
        viewport: { width: 1280, height: 720 },
      },
      dom: {
        selector: 'html > body > form > input#name',
        html: '<input id="name" value="x">',
        className: 'field',
        tagName: 'input',
        isFocused: true,
      },
    };

    const normalized = normalizeBoundedSnapshot(snapshot, 1700000000123);
    assert.equal(normalized.environment.url, snapshot.environment.url);
    assert.equal(normalized.environment.title, snapshot.environment.title);
    assert.equal(normalized.environment.browser, snapshot.environment.browser);
    assert.equal(normalized.environment.platform, snapshot.environment.platform);
    assert.deepEqual(normalized.environment.viewport, snapshot.environment.viewport);
    assert.equal(normalized.environment.timestamp, 1700000000123);
    assert.deepEqual(normalized.dom, snapshot.dom);
  });

  test('observation envelope separates payload, acquisition and browser provenance', () => {
    const snapshot = snapshotProbe();
    const result: InjectionResultLike = { frameId: 0, documentId: 'abc-doc' };
    const observation = makeBoundedObservation(snapshot, result, 7, 1700000000123);

    assert.equal(observation.acquisition, 'chrome-scripting');
    assert.equal(observation.provenance.tabId, 7);
    assert.equal(observation.provenance.frameId, 0);
    assert.equal(observation.provenance.documentId, 'abc-doc');
    assert.deepEqual(observation.payload, normalizeBoundedSnapshot(snapshot, 1700000000123));
  });

  test('observation envelope does not invent absent browser identities', () => {
    const snapshot = snapshotProbe();
    const result: InjectionResultLike = { frameId: 0 };
    const observation = makeBoundedObservation(snapshot, result, 3, 0);

    assert.equal(observation.provenance.tabId, 3);
    assert.equal(observation.provenance.frameId, 0);
    assert.equal(observation.provenance.documentId, undefined);
    assert.equal(observation.provenance.worldId, undefined);
  });

  test('bounded probe executes only in the trusted background; no pre-SNITCH content bundle', () => {
    // chrome.scripting is not available to content-script contexts, so the
    // DEVPEEPER bounded probe must run from the background service worker. The
    // pre-SNITCH rolling-cache content bundle has been removed entirely: there
    // must be no extension/content script that collects evidence before SNITCH,
    // and only the background may own chrome.scripting execution.
    const root = process.cwd();
    assert.equal(
      existsSync(join(root, 'extension', 'content')),
      false,
      'no content bridge / rolling-cache script may pre-empt SNITCH',
    );
    const backgroundSource = readFileSync(
      join(root, 'extension', 'background', 'index.ts'),
      'utf8',
    );
    assert.ok(
      backgroundSource.includes('chrome.scripting'),
      'background must own the chrome.scripting bounded-probe execution',
    );
  });
});

describe('DEVPEEPER Chromium observation foundation', () => {
  interface MockTransport extends DebuggerTransport {
    attachCalls: Array<{ target: DebuggerTarget; version: string }>;
    detachCalls: Array<DebuggerTarget>;
    commands: Array<{ method: string; params?: unknown }>;
    emitEvent(target: DebuggerTarget, method: string, params?: unknown): void;
    emitDetach(target: DebuggerTarget, reason: string): void;
  }

  function makeTransport(): MockTransport {
    const eventListeners: Array<
      (target: DebuggerTarget, method: string, params?: unknown) => void
    > = [];
    const detachListeners: Array<(target: DebuggerTarget, reason: string) => void> = [];

    const transport: MockTransport = {
      attachCalls: [],
      detachCalls: [],
      commands: [],
      attach: async (target, version) => {
        transport.attachCalls.push({ target, version });
      },
      detach: async (target) => {
        transport.detachCalls.push(target);
      },
      sendCommand: async (_target, method, params) => {
        transport.commands.push({ method, params });
        return {};
      },
      onEvent(listener) {
        eventListeners.push(listener);
        return () => {
          const i = eventListeners.indexOf(listener);
          if (i >= 0) eventListeners.splice(i, 1);
        };
      },
      onDetach(listener) {
        detachListeners.push(listener);
        return () => {
          const i = detachListeners.indexOf(listener);
          if (i >= 0) detachListeners.splice(i, 1);
        };
      },
      emitEvent(target, method, params) {
        for (const l of [...eventListeners]) l(target, method, params);
      },
      emitDetach(target, reason) {
        for (const l of [...detachListeners]) l(target, reason);
      },
    };

    return transport;
  }

  test('lifecycle: not running until start, running after start, stopped after stop', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(5, transport);

    assert.equal(observer.isRunning(), false);
    await observer.start();
    assert.equal(observer.isRunning(), true);
    await observer.stop();
    assert.equal(observer.isRunning(), false);
  });

  test('start attaches to the bound tab and enables only the minimal domains', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(9, transport);

    await observer.start();

    assert.equal(transport.attachCalls.length, 1);
    assert.deepEqual(transport.attachCalls[0].target, { tabId: 9 });
    assert.ok(transport.attachCalls[0].version.length > 0);

    assert.deepEqual(
      transport.commands.map((c) => c.method),
      ['Page.enable', 'Runtime.enable', 'Network.enable'],
    );
  });

  test('transactional start: partial enable failure detaches, unsubscribes, and stays reusable', async () => {
    const detachCalls: DebuggerTarget[] = [];
    let subscribed = 0;
    let unsubscribed = 0;
    const failOn = new Set<string>(['Runtime.enable']);

    const transport: DebuggerTransport = {
      attach: async () => undefined,
      detach: async (target) => {
        detachCalls.push(target);
      },
      sendCommand: async (_target, method) => {
        if (failOn.has(method)) throw new Error(`enable failed: ${method}`);
        return {};
      },
      onEvent: () => {
        subscribed += 1;
        return () => {
          unsubscribed += 1;
        };
      },
      onDetach: () => {
        subscribed += 1;
        return () => {
          unsubscribed += 1;
        };
      },
    };

    const observer = new ChromiumObserver(5, transport);

    // First start fails part-way through enabling domains.
    await assert.rejects(() => observer.start(), /enable failed: Runtime\.enable/);
    assert.equal(observer.isRunning(), false, 'observer must not be running after failed start');
    assert.equal(detachCalls.length, 1, 'failed start must detach the debugger target');
    assert.deepEqual(detachCalls[0], { tabId: 5 });
    assert.equal(
      subscribed - unsubscribed,
      0,
      'all listeners from the failed attempt must be unsubscribed',
    );

    // A retry must not accumulate more active listeners than a clean start.
    await assert.rejects(() => observer.start(), /enable failed: Runtime\.enable/);
    assert.equal(observer.isRunning(), false);
    assert.equal(detachCalls.length, 2, 'each failed attempt detaches again (reusable)');
    assert.equal(
      subscribed - unsubscribed,
      0,
      'retry must not double the active listener count',
    );
  });

  test('detach during startup invalidates the attempt and start() finishes non-running (BUG D)', async () => {
    const detachCalls: DebuggerTarget[] = [];
    const detachListeners: Array<(target: DebuggerTarget, reason: string) => void> = [];
    let releaseEnable: (() => void) | null = null;
    const enableGate = new Promise<void>((resolve) => {
      releaseEnable = resolve;
    });

    const transport: DebuggerTransport = {
      attach: async () => undefined,
      detach: async (target) => {
        detachCalls.push(target);
      },
      sendCommand: async (_target, method) => {
        if (method === 'Runtime.enable') await enableGate; // hold the enable pending
        return {};
      },
      onEvent: () => () => undefined,
      onDetach: (listener) => {
        detachListeners.push(listener);
        return () => {
          const i = detachListeners.indexOf(listener);
          if (i >= 0) detachListeners.splice(i, 1);
        };
      },
    };

    const observer = new ChromiumObserver(5, transport);

    const startPromise = observer.start();
    // Let start() progress: attach resolves, listeners subscribe, and Page.enable
    // resolves before Runtime.enable blocks on the gate.
    await new Promise((resolve) => setTimeout(resolve, 0));
    // Fire the matching detach while Runtime.enable is still pending.
    for (const listener of [...detachListeners]) listener({ tabId: 5 }, 'crashed');
    // Now let the pending enable resolve and start() finish.
    releaseEnable!();
    await startPromise;

    assert.equal(
      observer.isRunning(),
      false,
      'a start invalidated by an in-flight detach must not end running',
    );
    assert.equal(
      detachCalls.length,
      0,
      'no second detach is required to correct state after an in-flight detach',
    );

    // A later explicit retry is still possible: the invalidation latch resets.
    await observer.start();
    assert.equal(
      observer.isRunning(),
      true,
      'a retry after an invalidated attempt must be able to start cleanly',
    );
  });

  test('accepts instrumentation only for the active attachment tab', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    // Event for a different tab is ignored.
    transport.emitEvent({ tabId: 99 }, 'Page.frameNavigated', {
      frame: { id: 0, loaderId: 'other-loader' },
    });
    assert.equal(observer.drain().length, 0);

    transport.emitEvent({ tabId: 3 }, 'Page.frameNavigated', {
      frame: { id: 0, loaderId: 'loader-1' },
      timestamp: 1700000000000,
    });
    const buffered = observer.drain();
    assert.equal(buffered.length, 1);
    assert.equal(buffered[0].provenance.tabId, 3);
  });

  test('preserves browser provenance on a browser-observed observation', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(7, transport);
    await observer.start();

    transport.emitEvent({ tabId: 7 }, 'Page.frameNavigated', {
      frame: { id: 11, loaderId: 'loader-abc' },
      timestamp: 1700000000000,
    });
    transport.emitEvent({ tabId: 7 }, 'Page.frameNavigated', {
      frame: { id: 11, loaderId: 'loader-abc' },
      timestamp: 1700000000999,
    });

    const drained = observer.poll();
    assert.equal(drained.length, 2);
    for (const observation of drained) {
      assert.equal(observation.acquisition, 'chrome-debugger');
      assert.equal(observation.method, 'Page.frameNavigated');
      assert.equal(observation.provenance.tabId, 7);
      assert.equal(observation.provenance.frameId, 11);
      assert.equal(observation.provenance.loaderId, 'loader-abc');
      assert.equal(typeof observation.provenance.timestamp, 'number');
    }
  });

  test('only recognized foundation events are elevated to observations', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(4, transport);
    await observer.start();

    transport.emitEvent({ tabId: 4 }, 'Page.someOtherEvent', { foo: 1 });
    assert.equal(observer.drain().length, 0);

    transport.emitEvent({ tabId: 4 }, 'Page.frameNavigated', {
      frame: { id: 0, loaderId: 'l' },
    });
    assert.equal(observer.drain().length, 1);
  });

  test('Chrome-initiated detach stops the observer and clears stale observations', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(6, transport);
    await observer.start();

    transport.emitEvent({ tabId: 6 }, 'Page.frameNavigated', {
      frame: { id: 0, loaderId: 'l' },
    });
    assert.equal(observer.isRunning(), true);

    transport.emitDetach({ tabId: 6 }, 'target_closed');
    assert.equal(observer.isRunning(), false);
    assert.equal(observer.drain().length, 0);
  });

  test('detach from a different tab is ignored', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(6, transport);
    await observer.start();

    transport.emitDetach({ tabId: 999 }, 'target_closed');
    assert.equal(observer.isRunning(), true);
  });

  test('stop detaches cleanly and a detach error does not break the caller', async () => {
    const transport = makeTransport();
    transport.detach = async (target) => {
      transport.detachCalls.push(target);
      throw new Error('already detached');
    };
    const observer = new ChromiumObserver(2, transport);

    await observer.start();
    await observer.stop();
    assert.equal(observer.isRunning(), false);
    assert.equal(transport.detachCalls.length, 1);
  });
});



describe('DEVPEEPER browser-observed console + runtime errors', () => {
  interface MockTransport extends DebuggerTransport {
    attachCalls: Array<{ target: DebuggerTarget; version: string }>;
    detachCalls: Array<DebuggerTarget>;
    commands: Array<{ method: string; params?: unknown }>;
    emitEvent(target: DebuggerTarget, method: string, params?: unknown): void;
    emitDetach(target: DebuggerTarget, reason: string): void;
  }

  function makeTransport(): MockTransport {
    const eventListeners: Array<
      (target: DebuggerTarget, method: string, params?: unknown) => void
    > = [];
    const detachListeners: Array<(target: DebuggerTarget, reason: string) => void> = [];

    const transport: MockTransport = {
      attachCalls: [],
      detachCalls: [],
      commands: [],
      attach: async (target, version) => {
        transport.attachCalls.push({ target, version });
      },
      detach: async (target) => {
        transport.detachCalls.push(target);
      },
      sendCommand: async (_target, method, params) => {
        transport.commands.push({ method, params });
        return {};
      },
      onEvent(listener) {
        eventListeners.push(listener);
        return () => {
          const i = eventListeners.indexOf(listener);
          if (i >= 0) eventListeners.splice(i, 1);
        };
      },
      onDetach(listener) {
        detachListeners.push(listener);
        return () => {
          const i = detachListeners.indexOf(listener);
          if (i >= 0) detachListeners.splice(i, 1);
        };
      },
      emitEvent(target, method, params) {
        for (const l of [...eventListeners]) l(target, method, params);
      },
      emitDetach(target, reason) {
        for (const l of [...detachListeners]) l(target, reason);
      },
    };

    return transport;
  }

  test('start enables Page, Runtime and Network domains', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(1, transport);
    await observer.start();

    const methods = transport.commands.map((c) => c.method);
    assert.ok(methods.includes('Page.enable'));
    assert.ok(methods.includes('Runtime.enable'));
    assert.ok(methods.includes('Network.enable'));
  });

  test('Runtime.consoleAPICalled normalizes supported levels with message and stack', async () => {
    const entry = normalizeConsoleApi({
      type: 'error',
      timestamp: 1700000000.5,
      executionContextId: 12,
      args: [
        { type: 'string', value: 'boom:' },
        { type: 'number', value: 500 },
      ],
      stackTrace: {
        callFrames: [{ functionName: 'fetchData', url: 'app.js', lineNumber: 9, columnNumber: 3 }],
      },
    });

    assert.ok(entry);
    assert.equal(entry!.level, 'error');
    assert.equal(entry!.message, 'boom: 500');
    assert.equal(entry!.timestamp, 1700000000500);
    assert.ok(entry!.stack!.includes('fetchData'));
    assert.ok(entry!.stack!.includes('app.js:10:4'));
  });

  test('console timestamp normalizes seconds to ms and leaves ms unchanged', () => {
    // Unix seconds input is scaled to milliseconds.
    const seconds = normalizeConsoleApi({
      type: 'log',
      timestamp: 1_788_000_000,
      args: [{ type: 'string', value: 'now' }],
    });
    assert.equal(seconds!.timestamp, 1_788_000_000_000);

    // Unix milliseconds input is preserved unchanged (not scaled again).
    const milliseconds = normalizeConsoleApi({
      type: 'log',
      timestamp: 1_788_000_000_000,
      args: [{ type: 'string', value: 'now' }],
    });
    assert.equal(milliseconds!.timestamp, 1_788_000_000_000);
  });

  test('console type mapping and unsupported types are ignored', () => {
    assert.equal(normalizeConsoleApi({ type: 'log', args: [{ type: 'string', value: 'x' }] })!.level, 'log');
    assert.equal(normalizeConsoleApi({ type: 'info', args: [{ type: 'string', value: 'x' }] })!.level, 'info');
    assert.equal(normalizeConsoleApi({ type: 'warning', args: [{ type: 'string', value: 'x' }] })!.level, 'warn');
    assert.equal(normalizeConsoleApi({ type: 'debug', args: [{ type: 'string', value: 'x' }] })!.level, 'debug');
    // Unsupported console types are not elevated.
    assert.equal(normalizeConsoleApi({ type: 'table', args: [{ type: 'string', value: 'x' }] }), null);
    assert.equal(normalizeConsoleApi({ type: 'dir', args: [{ type: 'string', value: 'x' }] }), null);
  });

  test('Runtime.exceptionThrown normalizes without invented promise_rejection type', () => {
    const entry = normalizeExceptionThrown({
      timestamp: 1700000000,
      executionContextId: 5,
      exceptionDetails: {
        exceptionId: 3,
        text: 'Uncaught Error: boom',
        scriptId: '42',
        url: 'https://example.com/app.js',
        lineNumber: 7,
        columnNumber: 2,
        exception: {
          type: 'object',
          subtype: 'error',
          description: 'Error: boom\n    at fn (https://example.com/app.js:8:4)',
        },
      },
    });

    assert.ok(entry);
    assert.equal(entry!.type, 'unhandled_exception');
    assert.equal(entry!.message, 'Uncaught Error: boom');
    assert.equal(entry!.filename, 'https://example.com/app.js');
    assert.equal(entry!.lineno, 7);
    assert.equal(entry!.colno, 2);
    assert.ok(entry!.stack.includes('fn'));
  });

  test('browser-observed exception does not fabricate values Chrome omitted', () => {
    const entry = normalizeExceptionThrown({
      exceptionDetails: { exceptionId: 1, text: 'boom' },
    });
    assert.ok(entry);
    assert.equal(entry!.type, 'unhandled_exception');
    assert.equal(entry!.message, 'boom');
    assert.equal(entry!.filename, undefined);
    assert.equal(entry!.lineno, undefined);
    assert.equal(entry!.colno, undefined);
    assert.equal(entry!.stack, '');
  });

  test('observer accumulates console and error entries for the active tab', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(8, transport);
    await observer.start();

    transport.emitEvent({ tabId: 8 }, 'Runtime.consoleAPICalled', {
      type: 'log',
      timestamp: 1700000000,
      executionContextId: 1,
      args: [{ type: 'string', value: 'hello' }],
    });
    transport.emitEvent({ tabId: 8 }, 'Runtime.exceptionThrown', {
      timestamp: 1700000001,
      executionContextId: 1,
      exceptionDetails: { exceptionId: 1, text: 'boom' },
    });

    assert.equal(observer.getConsoleEntries().length, 1);
    assert.equal(observer.getConsoleEntries()[0].message, 'hello');
    assert.equal(observer.getJsErrorEntries().length, 1);
    assert.equal(observer.getJsErrorEntries()[0].message, 'boom');

    // Both are also retained as browser-observed observations with provenance.
    const drained = observer.poll();
    assert.equal(drained.length, 2);
    for (const observation of drained) {
      assert.equal(observation.acquisition, 'chrome-debugger');
      assert.equal(observation.provenance.tabId, 8);
    }
  });

  test('events from a different tab are rejected', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(8, transport);
    await observer.start();

    transport.emitEvent({ tabId: 999 }, 'Runtime.consoleAPICalled', {
      type: 'error',
      args: [{ type: 'string', value: 'forged' }],
    });
    transport.emitEvent({ tabId: 999 }, 'Runtime.exceptionThrown', {
      exceptionDetails: { exceptionId: 1, text: 'forged' },
    });

    assert.equal(observer.getConsoleEntries().length, 0);
    assert.equal(observer.getJsErrorEntries().length, 0);
    assert.equal(observer.poll().length, 0);
  });

  test('console history is bounded at 200 and errors at 50', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(8, transport);
    await observer.start();

    for (let i = 0; i < 210; i += 1) {
      transport.emitEvent({ tabId: 8 }, 'Runtime.consoleAPICalled', {
        type: 'log',
        args: [{ type: 'number', value: i }],
      });
    }
    for (let i = 0; i < 60; i += 1) {
      transport.emitEvent({ tabId: 8 }, 'Runtime.exceptionThrown', {
        exceptionDetails: { exceptionId: i, text: `err ${i}` },
      });
    }

    assert.equal(observer.getConsoleEntries().length, 200);
    assert.equal(observer.getJsErrorEntries().length, 50);
  });

  test('Chrome detach clears accumulated browser-observed entries', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(8, transport);
    await observer.start();

    transport.emitEvent({ tabId: 8 }, 'Runtime.consoleAPICalled', {
      type: 'log',
      args: [{ type: 'string', value: 'hello' }],
    });
    assert.equal(observer.getConsoleEntries().length, 1);

    transport.emitDetach({ tabId: 8 }, 'target_closed');
    assert.equal(observer.getConsoleEntries().length, 0);
    assert.equal(observer.getJsErrorEntries().length, 0);
    assert.equal(observer.poll().length, 0);
  });
});

describe('DEVPEEPER browser-observed network (DEVPEEPER-004)', () => {
  interface MockTransport extends DebuggerTransport {
    attachCalls: Array<{ target: DebuggerTarget; version: string }>;
    detachCalls: Array<DebuggerTarget>;
    commands: Array<{ method: string; params?: unknown }>;
    responseBodies: Record<string, { body: string; base64Encoded?: boolean }>;
    getResponseBodyErrors: string[];
    emitEvent(target: DebuggerTarget, method: string, params?: unknown): void;
    emitDetach(target: DebuggerTarget, reason: string): void;
  }

  function makeTransport(): MockTransport {
    const eventListeners: Array<
      (target: DebuggerTarget, method: string, params?: unknown) => void
    > = [];
    const detachListeners: Array<(target: DebuggerTarget, reason: string) => void> = [];

    const transport: MockTransport = {
      attachCalls: [],
      detachCalls: [],
      commands: [],
      responseBodies: {},
      getResponseBodyErrors: [],
      attach: async (target, version) => {
        transport.attachCalls.push({ target, version });
      },
      detach: async (target) => {
        transport.detachCalls.push(target);
      },
      sendCommand: async (_target, method, params) => {
        transport.commands.push({ method, params });
        if (method === 'Network.getResponseBody') {
          const requestId = (params as { requestId?: string }).requestId ?? '';
          if (transport.getResponseBodyErrors.includes(requestId)) {
            throw new Error('body unavailable');
          }
          return transport.responseBodies[requestId] ?? {};
        }
        return {};
      },
      onEvent(listener) {
        eventListeners.push(listener);
        return () => {
          const i = eventListeners.indexOf(listener);
          if (i >= 0) eventListeners.splice(i, 1);
        };
      },
      onDetach(listener) {
        detachListeners.push(listener);
        return () => {
          const i = detachListeners.indexOf(listener);
          if (i >= 0) detachListeners.splice(i, 1);
        };
      },
      emitEvent(target, method, params) {
        for (const l of [...eventListeners]) l(target, method, params);
      },
      emitDetach(target, reason) {
        for (const l of [...detachListeners]) l(target, reason);
      },
    };

    return transport;
  }

  test('normalizes an HTTP >=400 response into a NetworkEntry with bounded body preview', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    const rid = 'req-1';
    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: rid,
      timestamp: 100.0,
      loaderId: 'loader-1',
      frameId: 7,
      request: {
        url: 'https://api.example.com/missing',
        method: 'GET',
        headers: { 'X-Auth': 'token' },
      },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: rid,
      timestamp: 105.0,
      response: { status: 404 },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', {
      requestId: rid,
      timestamp: 110.0,
    });

    transport.responseBodies[rid] = { body: '{"error": "Not Found"}', base64Encoded: false };

    const entries = await observer.getNetworkEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].url, 'https://api.example.com/missing');
    assert.equal(entries[0].method, 'GET');
    assert.equal(entries[0].status, 404);
    assert.equal(entries[0].duration, 10000);
    assert.equal(entries[0].responsePreview, '{"error": "Not Found"}');
    assert.deepEqual(entries[0].requestHeaders, { 'X-Auth': 'token' });

    const bodyCmd = transport.commands.find((c) => c.method === 'Network.getResponseBody');
    assert.ok(bodyCmd);
    assert.deepEqual((bodyCmd.params as Record<string, unknown>).requestId, rid);
  });

  test('network observations and getNetworkEntries carry Chromium provenance', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: 'req-9',
      timestamp: 1.0,
      loaderId: 'loader-abc',
      frameId: 4,
      request: { url: 'https://api.example.com/x', method: 'GET' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: 'req-9',
      response: { status: 500 },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', {
      requestId: 'req-9',
      timestamp: 2.0,
    });

    const observations = observer.drain();
    assert.equal(observations.length, 3);
    for (const observation of observations) {
      assert.equal(observation.acquisition, 'chrome-debugger');
      assert.equal(observation.provenance.tabId, 3);
    }
    assert.equal(observations[0].provenance.requestId, 'req-9');
    assert.equal(observations[0].provenance.loaderId, 'loader-abc');
    assert.equal(observations[0].provenance.frameId, 4);
    assert.equal(typeof observations[0].provenance.timestamp, 'number');
  });

  test('a browser-reported failure normalizes to status 0 with errorText preview', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: 'req-fail',
      timestamp: 10.0,
      request: { url: 'https://api.example.com/down', method: 'POST' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFailed', {
      requestId: 'req-fail',
      timestamp: 15.0,
      errorText: 'net::ERR_CONNECTION_REFUSED',
    });

    const entries = await observer.getNetworkEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].status, 0);
    assert.equal(entries[0].responsePreview, 'net::ERR_CONNECTION_REFUSED');
    assert.equal(entries[0].duration, 5000);

    // A failed request has no body to fetch.
    assert.equal(transport.commands.some((c) => c.method === 'Network.getResponseBody'), false);
  });

  test('successful requests are not retained as network evidence', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: 'req-200',
      timestamp: 0.0,
      request: { url: 'https://api.example.com/ok', method: 'GET' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: 'req-200',
      response: { status: 200 },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', {
      requestId: 'req-200',
      timestamp: 1.0,
    });

    assert.equal((await observer.getNetworkEntries()).length, 0);
  });

  test('wrong-tab network events do not feed the tracker', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    transport.emitEvent({ tabId: 999 }, 'Network.requestWillBeSent', {
      requestId: 'forged',
      timestamp: 0.0,
      request: { url: 'https://evil.example.com', method: 'GET' },
    });
    transport.emitEvent({ tabId: 999 }, 'Network.responseReceived', {
      requestId: 'forged',
      response: { status: 500 },
    });
    transport.emitEvent({ tabId: 999 }, 'Network.loadingFinished', {
      requestId: 'forged',
      timestamp: 1.0,
    });

    assert.equal((await observer.getNetworkEntries()).length, 0);
    assert.equal(observer.poll().length, 0);
  });

  test('network history is bounded at NETWORK_MAX_ENTRIES, dropping the oldest', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    for (let i = 0; i < 120; i += 1) {
      const rid = `req-${i}`;
      transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
        requestId: rid,
        timestamp: i,
        request: { url: `https://api.example.com/${i}`, method: 'GET' },
      });
      transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
        requestId: rid,
        response: { status: 404 },
      });
      transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', {
        requestId: rid,
        timestamp: i + 1,
      });
    }

    const entries = await observer.getNetworkEntries();
    assert.equal(entries.length, 100);
    assert.equal(entries[0].url, 'https://api.example.com/20');
    assert.equal(entries[entries.length - 1].url, 'https://api.example.com/119');
  });

  test('a getResponseBody failure keeps the entry with an empty preview', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    const rid = 'req-nobody';
    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: rid,
      timestamp: 0.0,
      request: { url: 'https://api.example.com/x', method: 'GET' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: rid,
      response: { status: 500 },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', {
      requestId: rid,
      timestamp: 1.0,
    });
    transport.getResponseBodyErrors.push(rid);

    const entries = await observer.getNetworkEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].status, 500);
    assert.equal(entries[0].responsePreview, '');
  });

  test('base64 response bodies are decoded into the bounded preview', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    const rid = 'req-b64';
    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: rid,
      timestamp: 0.0,
      request: { url: 'https://api.example.com/x', method: 'GET' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: rid,
      response: { status: 404 },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', {
      requestId: rid,
      timestamp: 1.0,
    });
    transport.responseBodies[rid] = {
      body: Buffer.from('binary response content').toString('base64'),
      base64Encoded: true,
    };

    const entries = await observer.getNetworkEntries();
    assert.equal(entries[0].responsePreview, 'binary response content');
  });

  test('an in-flight HTTP failure is finalized by getNetworkEntries (SNITCH-time)', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: 'req-inflight',
      timestamp: 0.0,
      request: { url: 'https://api.example.com/late', method: 'GET' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: 'req-inflight',
      response: { status: 503 },
    });
    // No loadingFinished/loadingFailed yet.

    const entries = await observer.getNetworkEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].status, 503);
  });

  test('a request with no response and no terminal event is never fabricated as a failure', () => {
    const tracker = new NetworkTracker();
    tracker.onRequestWillBeSent({
      requestId: 'stuck',
      timestamp: 1.0,
      request: { url: 'https://api.example/hang', method: 'GET' },
    });

    const result = tracker.finalize();
    assert.equal(result.entries.length, 0, 'undetermined must not become a status-0 entry');
    // Repeated finalize calls are harmless while the request stays in flight.
    tracker.finalize();
    assert.equal(tracker.finalize().entries.length, 0);
  });

  test('terminal network events arriving during getNetworkEntries are drained, not dropped', async () => {
    // Premature-finalization regression: a request whose terminal event is still
    // in Chromium's async delivery pipeline when the evidence snapshot starts
    // must survive into the entries. The bounded drain waits (lifecycle-tied,
    // hard deadline) and re-reads the undetermined set every tick.
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport, {
      networkDrain: {
        tickMs: 1,
        deadlineMs: 500,
        sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      },
    });
    await observer.start();

    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: 'req-late',
      timestamp: 10.0,
      request: { url: 'https://api.example.com/down', method: 'GET' },
    });
    // No responseReceived and no terminal event yet: the request is in-flight.
    const pending = observer.getNetworkEntries();

    // Deliver the transport failure while the drain is still within its bound.
    await new Promise((resolve) => setTimeout(resolve, 5));
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFailed', {
      requestId: 'req-late',
      timestamp: 12.0,
      errorText: 'net::ERR_CONNECTION_REFUSED',
    });

    const entries = await pending;
    assert.equal(entries.length, 1, 'a late loadingFailed must not be dropped');
    assert.equal(entries[0].status, 0);
    assert.equal(entries[0].responsePreview, 'net::ERR_CONNECTION_REFUSED');
  });

  test('Chrome detach clears accumulated network history', async () => {
    const transport = makeTransport();
    const observer = new ChromiumObserver(3, transport);
    await observer.start();

    transport.emitEvent({ tabId: 3 }, 'Network.requestWillBeSent', {
      requestId: 'req-a',
      timestamp: 0.0,
      request: { url: 'https://api.example.com/resource', method: 'GET' },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.responseReceived', {
      requestId: 'req-a',
      response: { status: 500 },
    });
    transport.emitEvent({ tabId: 3 }, 'Network.loadingFinished', { requestId: 'req-a', timestamp: 2.0 });

    transport.emitDetach({ tabId: 3 }, 'target_closed');
    assert.equal((await observer.getNetworkEntries()).length, 0);
  });
});

describe('SNITCHSHOT private buffer lifecycle', () => {
  function makeMemoryStorage(): SnitchshotStorageLike & { store: Map<string, unknown> } {
    const store = new Map<string, unknown>();
    return {
      store,
      get: async (key) => ({ [key]: store.get(key) }),
      set: async (items) => {
        for (const [k, v] of Object.entries(items)) store.set(k, v);
      },
      remove: async (key) => {
        store.delete(key);
      },
    };
  }

  function makeBuffer(storage: SnitchshotStorageLike & { store: Map<string, unknown> }) {
    return new SnitchshotBuffer(storage);
  }

  test('successful SNITCH fills an empty private buffer (EMPTY → OCCUPIED)', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    assert.equal(await buffer.isOccupied(), false);

    await buffer.fill('# DEVSNITCHER REPORT', 1);

    assert.equal(await buffer.isOccupied(), true);
    const record = await buffer.peek();
    assert.equal(record?.sourceTabId, 1);
    assert.ok(record?.report.startsWith('# DEVSNITCHER REPORT'));
    assert.ok(storage.store.has(SNITCHSHOT_BUFFER_KEY));
  });

  test('second SNITCH while occupied is refused without replacing the first', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    await buffer.fill('# FIRST REPORT', 1);

    await assert.rejects(
      buffer.fill('# SECOND REPORT', 2),
      /SNITCHSHOT pending/,
    );

    const record = await buffer.peek();
    assert.equal(record?.sourceTabId, 1);
    assert.equal(record?.report, '# FIRST REPORT');
  });

  test('successful owned paste clears the buffer (OCCUPIED → EMPTY)', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    await buffer.fill('# PASTE ME', 1);

    await buffer.clear();

    assert.equal(await buffer.isOccupied(), false);
    assert.equal(await buffer.peek(), null);
  });

  test('failed paste preserves the buffer; unsupported target is not consumed', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    await buffer.fill('# KEEP ME', 1);

    // Simulate a failed clipboard write (no clear called); the buffer still
    // holds the original report so the user can retry.
    const record = await buffer.peek();
    assert.equal(record?.report, '# KEEP ME');
    assert.ok(record, 'buffer must remain intact after a failed clipboard write');
  });

  test('tab switching does not clear the outstanding SNITCHSHOT', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    await buffer.fill('# PERSIST', 1);

    // The buffer is global (single key), not scoped to a tab id. Confirm that
    // nothing tied to a per-tab key can just disappear on a tab change, and that
    // an unrelated storage mutation leaves it intact.
    storage.store.set('devsnitcher:evidence-cache:v1:2', { version: 1 });

    assert.equal(storage.store.has(SNITCHSHOT_BUFFER_KEY), true);
    assert.equal(await buffer.isOccupied(), true);
    assert.equal((await buffer.peek())?.report, '# PERSIST');
  });

  test('a failed buffer clear throws rather than masquerading as cleared', async () => {
    const base = makeMemoryStorage();
    const storage = {
      ...base,
      remove: async () => {
        throw new Error('storage remove failed');
      },
    };
    const buffer = makeBuffer(storage);
    await buffer.fill('# AUTHENTIC', 5);

    await assert.rejects(
      buffer.clear(),
      /storage remove failed/,
      'a failed removal must surface so CLIPBOARD_CLEARED is never falsely sent',
    );

    // The SNITCHSHOT stays occupied and authoritative.
    assert.equal((await buffer.peek())?.report, '# AUTHENTIC');
    assert.equal(await buffer.isOccupied(), true);
  });

  test('a failed buffer read throws instead of masquerading as EMPTY', async () => {
    const base = makeMemoryStorage();
    const storage = {
      ...base,
      get: async () => {
        throw new Error('storage read failed');
      },
    };
    const buffer = makeBuffer(storage);

    await assert.rejects(
      buffer.peek(),
      /storage read failed/,
      'a storage failure must not be collapsed into an empty buffer',
    );
    await assert.rejects(buffer.isOccupied(), /storage read failed/);
  });

  test('a confirmed release clears the private buffer exactly once', async () => {
    const storage = makeMemoryStorage();
    let removeCalls = 0;
    storage.remove = async (key: string) => {
      removeCalls += 1;
      storage.store.delete(key);
    };
    const buffer = makeBuffer(storage);
    await buffer.fill('# RELEASE ONCE', 9);

    await buffer.clear();

    assert.equal(removeCalls, 1, 'release must clear the buffer exactly once');
    assert.equal(storage.store.has(SNITCHSHOT_BUFFER_KEY), false);
    assert.equal(await buffer.isOccupied(), false);
  });
});

describe('bounded SNITCH session lifecycle', () => {
  interface SessionMockTransport extends DebuggerTransport {
    attachCalls: DebuggerTarget[];
    detachCalls: DebuggerTarget[];
    failCommands: Set<string>;
    emitEvent(target: DebuggerTarget, method: string, params?: unknown): void;
  }

  function makeSessionTransport(): SessionMockTransport {
    const eventListeners: Array<
      (target: DebuggerTarget, method: string, params?: unknown) => void
    > = [];
    const transport: SessionMockTransport = {
      attachCalls: [],
      detachCalls: [],
      failCommands: new Set(),
      attach: async (target) => {
        transport.attachCalls.push(target);
      },
      detach: async (target) => {
        transport.detachCalls.push(target);
      },
      sendCommand: async (_target, method) => {
        if (transport.failCommands.has(method)) throw new Error(`command failed: ${method}`);
        return {};
      },
      onEvent(listener) {
        eventListeners.push(listener);
        return () => {
          const i = eventListeners.indexOf(listener);
          if (i >= 0) eventListeners.splice(i, 1);
        };
      },
      onDetach: () => () => undefined,
      emitEvent(target, method, params) {
        for (const l of [...eventListeners]) l(target, method, params);
      },
    };
    return transport;
  }

  function makeSessionDeps(overrides: Partial<{
    transport: SessionMockTransport;
    acquireBounded: () => Promise<{ environment: Evidence['environment']; dom: Evidence['dom'] }>;
    onComplete: (evidence: Evidence, ctx: SnitchSessionContext) => Promise<void>;
    onCancel?: (ctx: SnitchSessionContext) => void;
    networkDrain?: NetworkDrainOptions;
  }> = {}) {
    const transport = overrides.transport ?? makeSessionTransport();
    const deps = {
      transport: () => transport,
      isSupported: (url: string) => !url.startsWith('chrome://'),
      acquireBounded:
        overrides.acquireBounded ??
        (async () => ({
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        })),
      onComplete:
        overrides.onComplete ??
        (async () => {
          /* no-op */
        }),
      ...(overrides.onCancel ? { onCancel: overrides.onCancel } : {}),
      ...(overrides.networkDrain ? { networkDrain: overrides.networkDrain } : {}),
    };
    const session = new SnitchSessionManager(deps);
    return { transport, deps, session };
  }

  function ctx(overrides: Partial<SnitchSessionContext> = {}): SnitchSessionContext {
    return {
      tabId: 1,
      tabUrl: 'https://a.example',
      userNotes: '',
      screenshot: false,
      ...overrides,
    };
  }


  test('no debugger attaches without SNITCH (no auto-attach), and idle has no observer', () => {
    const { transport, session } = makeSessionDeps();
    // A fresh manager is idle and owns no attachment.
    assert.equal(session.isObserving(), false);
    assert.equal(session.attachedTabId(), undefined);
    assert.equal(transport.attachCalls.length, 0, 'nothing attaches until SNITCH');
    assert.equal(transport.detachCalls.length, 0);
  });

  test('SNITCH attaches only the selected tab, acquires it, then detaches', async () => {
    const { transport, session } = makeSessionDeps();
    await session.start(ctx({ tabId: 5, tabUrl: 'https://five.example' }));

    assert.equal(transport.attachCalls.length, 1);
    assert.deepEqual(transport.attachCalls[0], { tabId: 5 });
    assert.equal(transport.attachCalls[0].tabId, 5, 'acquisition binds the tab selected at SNITCH time');

    // Acquisition is synchronous with the reads: once start() resolves the
    // session has already completed and detached. No later activation can move
    // or resurrect it.
    assert.equal(session.isObserving(), false);
    assert.equal(session.attachedTabId(), undefined);
    assert.equal(transport.detachCalls.length, 1, 'completion detaches the observer');
  });

  test('SNITCH acquisition finishes when the reads finish — no harvest window', async () => {
    // A manually-controlled bounded probe: completion is gated on the probe
    // resolving, never on a six-second (or any) timer. The deps have no clock
    // and no scheduler.
    let resolveProbe!: () => void;
    const probePromise = new Promise<void>((resolve) => {
      resolveProbe = resolve;
    });
    let completed = false;
    const { session } = makeSessionDeps({
      acquireBounded: async () => {
        await probePromise;
        return {
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        };
      },
      onComplete: async () => {
        completed = true;
      },
    });

    let started = false;
    const startPromise = session.start(ctx()).then(() => {
      started = true;
    });

    // While the probe is still reading, acquisition is in flight and incomplete.
    assert.equal(completed, false, 'acquisition waits on its reads, not a timer');
    assert.equal(started, false);

    resolveProbe();
    await startPromise;

    assert.equal(completed, true, 'finalizes as soon as the actual reads complete');
    assert.ok(started);
  });

  test('required evidence completion produces the report and detaches', async () => {
    const captured: { evidence: Evidence | null } = { evidence: null };
    const { transport, session } = makeSessionDeps({
      onComplete: async (evidence) => {
        captured.evidence = evidence;
      },
    });

    await session.start(ctx());

    assert.ok(captured.evidence, 'a report must be produced once acquisition completes');
    assert.equal(captured.evidence!.environment.url, 'https://a.example');
    assert.equal(session.isObserving(), false, 'session must detach after completion');
    assert.equal(transport.attachCalls.length, 1);
    assert.equal(transport.detachCalls.length, 1, 'completion must detach the debugger');
  });

  test('an idle page still yields a snapshot report; empty prospective surfaces are legitimate', async () => {
    // No console/jsError/network events are delivered to the mock transport:
    // those surfaces are prospective-only after debugger attachment. The bounded
    // probe snapshot (environment/dom) is the on-demand diagnostic state, and
    // the empty prospective categories must NOT be fabricated or waited on.
    const captured: { evidence: Evidence | null } = { evidence: null };
    const { transport, session } = makeSessionDeps({
      onComplete: async (evidence) => {
        captured.evidence = evidence;
      },
    });

    await session.start(ctx());

    assert.ok(captured.evidence);
    assert.equal(captured.evidence!.environment.url, 'https://a.example');
    assert.deepEqual(captured.evidence!.console, [], 'console is prospective-only at SNITCH time');
    assert.deepEqual(captured.evidence!.jsErrors, [], 'jsErrors are prospective-only at SNITCH time');
    assert.deepEqual(captured.evidence!.network, [], 'network is prospective-only at SNITCH time');
    assert.equal(transport.attachCalls.length, 1, 'attached exactly the one SNITCH tab');
  });

  test('network failures generated during active acquisition survive into assembled Evidence.network', async () => {
    const captured: { evidence: Evidence | null } = { evidence: null };
    const transport = makeSessionTransport();
    const { session } = makeSessionDeps({
      transport,
      // Deliver the harness's failure lifecycles while the observer is attached
      // and before finalization: an HTTP 404 and a genuine transport failure.
      acquireBounded: async () => {
        transport.emitEvent({ tabId: 1 }, 'Network.requestWillBeSent', {
          requestId: 'n-404',
          timestamp: 1.0,
          request: { url: 'https://a.example/intentional-404', method: 'GET' },
        });
        transport.emitEvent({ tabId: 1 }, 'Network.responseReceived', {
          requestId: 'n-404',
          response: { status: 404 },
        });
        transport.emitEvent({ tabId: 1 }, 'Network.loadingFinished', {
          requestId: 'n-404',
          timestamp: 2.0,
        });
        transport.emitEvent({ tabId: 1 }, 'Network.requestWillBeSent', {
          requestId: 'n-refused',
          timestamp: 1.0,
          request: { url: 'http://127.0.0.1:9/x', method: 'GET' },
        });
        transport.emitEvent({ tabId: 1 }, 'Network.loadingFailed', {
          requestId: 'n-refused',
          timestamp: 1.5,
          errorText: 'net::ERR_CONNECTION_REFUSED',
        });
        return {
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        };
      },
      onComplete: async (evidence) => {
        captured.evidence = evidence;
      },
    });

    await session.start(ctx({ tabId: 1, tabUrl: 'https://a.example' }));

    assert.ok(captured.evidence);
    assert.equal(captured.evidence!.network.length, 2, 'both failure categories survive assembly');
    const http404 = captured.evidence!.network.find((e) => e.status === 404);
    const transportFail = captured.evidence!.network.find((e) => e.status === 0);
    assert.ok(http404, 'HTTP >=400 must survive into Evidence.network');
    assert.equal(http404!.url, 'https://a.example/intentional-404');
    assert.equal(http404!.method, 'GET');
    assert.ok(transportFail, 'loadingFailed must survive into Evidence.network as status 0');
    assert.equal(transportFail!.url, 'http://127.0.0.1:9/x');
    assert.equal(transportFail!.responsePreview, 'net::ERR_CONNECTION_REFUSED');
  });

  test('requested screenshot is carried into the completed evidence', async () => {
    const captured: { evidence: Evidence | null } = { evidence: null };
    const { session } = makeSessionDeps({
      onComplete: async (evidence) => {
        captured.evidence = evidence;
      },
    });

    await session.start(
      ctx({
        screenshot: true,
        screenshotInfo: { dataUrl: 'data:image/png;base64,AAA', width: 1, height: 1 },
      }),
    );

    assert.ok(captured.evidence, 'a report must be produced once acquisition completes');
    assert.equal(captured.evidence!.screenshot?.dataUrl, 'data:image/png;base64,AAA');
    assert.equal(captured.evidence!.screenshot?.width, 1);
  });

  test('CANCEL terminates an in-progress acquisition and does not resurrect', async () => {
    let resolveProbe!: () => void;
    const probePromise = new Promise<void>((resolve) => {
      resolveProbe = resolve;
    });
    let completed = false;
    const { transport, session } = makeSessionDeps({
      acquireBounded: async () => {
        await probePromise;
        return {
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        };
      },
      onComplete: async () => {
        completed = true;
      },
    });

    const startPromise = session.start(ctx({ tabId: 3 }));
    // Let acquisition reach the pending probe so the observer is attached.
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(session.isObserving(), true, 'acquisition is active while the probe reads');

    const canceled = await session.cancel();
    assert.equal(canceled, true);
    assert.equal(session.isObserving(), false, 'cancel must return the manager to idle');
    assert.equal(session.attachedTabId(), undefined);
    assert.equal(transport.detachCalls.length, 1, 'cancel must detach');

    // Resolving the abandoned probe must not resurrect the terminated session
    // or produce a report.
    resolveProbe();
    await startPromise;
    assert.equal(completed, false, 'cancel must discard the unfinished acquisition');
    assert.equal(session.isObserving(), false);
    assert.equal(transport.attachCalls.length, 1, 'no re-attach after terminal cancel');
    assert.equal(transport.detachCalls.length, 1);
  });

  test('a second SNITCH while one acquisition is live is refused', async () => {
    let resolveProbe!: () => void;
    const probePromise = new Promise<void>((resolve) => {
      resolveProbe = resolve;
    });
    const { transport, session } = makeSessionDeps({
      acquireBounded: async () => {
        await probePromise;
        return {
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        };
      },
    });

    const first = session.start(ctx({ tabId: 1 }));
    // Let the first acquisition reach the pending probe (observer attached)
    // before the second SNITCH attempts to start.
    await new Promise((resolve) => setTimeout(resolve, 0));
    const second = await session.start(ctx({ tabId: 2 }));
    assert.equal(second, false, 'one live acquisition is enforced globally');
    assert.equal(session.attachedTabId(), 1);
    assert.equal(transport.attachCalls.length, 1, 'no second observer attached');
    resolveProbe();
    await first;
  });

  test('closing the source tab terminates the session without migration', async () => {
    const { transport, session } = makeSessionDeps();
    await session.start(ctx({ tabId: 7 }));
    await session.handleRemoved(7);
    assert.equal(session.isObserving(), false);
    assert.equal(transport.detachCalls.length, 1);
    assert.equal(transport.attachCalls.length, 1, 'session never migrates to another tab');
  });

  test('cancel during the in-assembly network drain is terminal: no report stored', async () => {
    // Regression: getNetworkEntries' bounded drain (up to 1500ms) runs while the
    // session is still assembling evidence. A cancel in that window must stay
    // effective — the manager reports acquiring, detaches, and never delivers
    // evidence to onComplete for a canceled session.
    const captured: { evidence: Evidence | null } = { evidence: null };
    const transport = makeSessionTransport();
    const { session } = makeSessionDeps({
      transport,
      networkDrain: { tickMs: 5, deadlineMs: 30_000 },
      acquireBounded: async () => {
        // Leave one request undetermined so the drain spins during assembly.
        transport.emitEvent({ tabId: 1 }, 'Network.requestWillBeSent', {
          requestId: 'hold-drain',
          timestamp: 1.0,
          request: { url: 'https://a.example/slow', method: 'GET' },
        });
        return {
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        };
      },
      onComplete: async (evidence) => {
        captured.evidence = evidence;
      },
    });

    const startPromise = session.start(ctx());
    // Assembly is now inside the drain (undetermined set non-empty).
    await new Promise((resolve) => setTimeout(resolve, 20));
    const canceled = await session.cancel();

    assert.equal(canceled, true, 'cancel must report a live session was canceled');
    assert.equal(session.isObserving(), false, 'cancel returns the manager to idle');
    assert.equal(transport.detachCalls.length, 1, 'cancel detaches the debugger');

    // Stopping the observer clears the tracker, collapsing the drain; the
    // winding-down acquisition must finish without storing anything.
    await startPromise;

    assert.equal(
      captured.evidence,
      null,
      'a canceled session must never deliver evidence to onComplete',
    );
    assert.equal(transport.detachCalls.length, 1, 'no second detach after cancel');
  });

  test('a second SNITCH while evidence assembly is inside the network drain is refused', async () => {
    // Regression: the drain widened the in-assembly window; a second SNITCH in
    // that window must still be refused (one live session globally).
    const captured: { evidence: Evidence | null } = { evidence: null };
    const transport = makeSessionTransport();
    const { session } = makeSessionDeps({
      transport,
      networkDrain: { tickMs: 5, deadlineMs: 30_000 },
      acquireBounded: async () => {
        transport.emitEvent({ tabId: 1 }, 'Network.requestWillBeSent', {
          requestId: 'hold-drain',
          timestamp: 1.0,
          request: { url: 'https://a.example/slow', method: 'GET' },
        });
        return {
          environment: {
            url: 'https://a.example',
            title: 'A',
            browser: 'Chrome',
            platform: 'Test',
            viewport: { width: 1280, height: 720 },
            timestamp: 1,
          },
          dom: null,
        };
      },
      onComplete: async (evidence) => {
        captured.evidence = evidence;
      },
    });

    const startPromise = session.start(ctx({ tabId: 1 }));
    await new Promise((resolve) => setTimeout(resolve, 20));

    const secondAccepted = await session.start(ctx({ tabId: 2 }));
    assert.equal(secondAccepted, false, 'in-assembly acquisition is a live session');
    assert.equal(transport.attachCalls.length, 1, 'no second observer attached');

    // Deliver the terminal event so the first acquisition completes promptly.
    transport.emitEvent({ tabId: 1 }, 'Network.loadingFailed', {
      requestId: 'hold-drain',
      timestamp: 2.0,
      errorText: 'net::ERR_CONNECTION_REFUSED',
    });
    await startPromise;

    assert.ok(captured.evidence, 'the original session completes normally afterwards');
    assert.equal(captured.evidence!.network.length, 1, 'the retained failure survives assembly');
    assert.equal(captured.evidence!.network[0].status, 0);
  });
});

describe('SNITCHSHOT clipboard release', () => {
  function makeMemoryStorage(): SnitchshotStorageLike & { store: Map<string, unknown> } {
    const store = new Map<string, unknown>();
    return {
      store,
      get: async (key) => ({ [key]: store.get(key) }),
      set: async (items) => {
        for (const [k, v] of Object.entries(items)) store.set(k, v);
      },
      remove: async (key) => {
        store.delete(key);
      },
    };
  }

  function makeBuffer(storage: SnitchshotStorageLike & { store: Map<string, unknown> }) {
    return new SnitchshotBuffer(storage);
  }

  test('successful system clipboard transfer clears the private SNITCHSHOT', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    await buffer.fill('# RELEASE ME', 1);

    // Simulate the confirmed OS clipboard write, then the release confirmation.
    assert.equal(storage.store.has(SNITCHSHOT_BUFFER_KEY), true);
    await buffer.clear();
    assert.equal(storage.store.has(SNITCHSHOT_BUFFER_KEY), false, 'buffer cleared after release');
    assert.equal(await buffer.isOccupied(), false);
  });

  test('failed clipboard transfer preserves the private SNITCHSHOT', async () => {
    const storage = makeMemoryStorage();
    const buffer = makeBuffer(storage);
    await buffer.fill('# KEEP ME', 1);

    // A failed write leaves the buffer untouched so the user can retry.
    assert.equal((await buffer.peek())?.report, '# KEEP ME');
    assert.equal(await buffer.isOccupied(), true);
    assert.equal(storage.store.has(SNITCHSHOT_BUFFER_KEY), true);
  });
});

describe('SNITCHSHOT clipboard writer', () => {
  interface ClipboardLike {
    writeText?: (text: string) => Promise<void>;
    write?: (items: unknown) => Promise<void>;
  }

  function installMockClipboard(clipboard: ClipboardLike | null): () => void {
    const previous = (navigator as unknown as { clipboard?: ClipboardLike }).clipboard;
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboard,
      writable: true,
      configurable: true,
    });
    return () => {
      Object.defineProperty(navigator, 'clipboard', {
        value: previous,
        writable: true,
        configurable: true,
      });
    };
  }

  function installExecCommand(impl: (command: string) => boolean): () => void {
    const captured: Array<{ selected: string; command: string }> = [];
    const prev = (document as any).execCommand;
    (document as any).execCommand = (command: string) => {
      const textarea = document.activeElement as HTMLTextAreaElement | null;
      captured.push({
        command,
        selected: textarea && textarea.tagName === 'TEXTAREA' ? textarea.value : '',
      });
      return impl(command);
    };
    Object.defineProperty((window as any), '__copiedTexts', {
      value: captured,
      writable: true,
      configurable: true,
    });
    return () => {
      (document as any).execCommand = prev;
      delete (window as any).__copiedTexts;
    };
  }

  function capturedSelections(): Array<{ selected: string; command: string }> {
    return (window as any).__copiedTexts ?? [];
  }

  test('ordinary text copy ignores a resolved navigator.clipboard.writeText promise', async () => {
    // A resolved async Clipboard API promise must NOT authorize text release.
    let modernCalled = false;
    const restoreClipboard = installMockClipboard({
      writeText: async () => {
        modernCalled = true;
      },
    });
    const restoreExec = installExecCommand(() => true);
    try {
      await writeToClipboard({ text: '# FULL REPORT\nbody' });

      assert.equal(
        modernCalled,
        false,
        'navigator.clipboard.writeText must not be the release authority for text',
      );
      const captured = capturedSelections();
      assert.equal(captured.length, 1, 'the authoritative DOM copy path must run');
      assert.equal(captured[0].command, 'copy');
      assert.equal(
        captured[0].selected,
        '# FULL REPORT\nbody',
        'the complete report must be selected for the authoritative OS copy',
      );
    } finally {
      restoreClipboard();
      restoreExec();
    }
  });

  test('authoritative text copy succeeds via the DOM copy path', async () => {
    const restoreClipboard = installMockClipboard(null);
    const restoreExec = installExecCommand(() => true);
    try {
      await writeToClipboard({ text: '# FULL REPORT\nbody' });
      const captured = capturedSelections();
      assert.equal(captured.length, 1);
      assert.equal(captured[0].command, 'copy');
      assert.equal(
        captured[0].selected,
        '# FULL REPORT\nbody',
        'the whole report must be selected for the OS copy',
      );
    } finally {
      restoreClipboard();
      restoreExec();
    }
  });

  test('execCommand copy returning false surfaces the failure instead of a false success', async () => {
    const restoreClipboard = installMockClipboard(null);
    const restoreExec = installExecCommand(() => false);
    try {
      await assert.rejects(
        writeToClipboard({ text: '# KEEP ME' }),
        /clipboard rejected/i,
        'a failed OS write must throw rather than pretend success',
      );
      const captured = capturedSelections();
      assert.equal(captured.length, 1, 'it must still attempt the copy');
      assert.equal(captured[0].selected, '# KEEP ME');
    } finally {
      restoreClipboard();
      restoreExec();
    }
  });

  test('text-only writeTextViaDomCopy reuses a focused, selectable offscreen textarea', () => {
    const restoreExec = installExecCommand(() => true);
    try {
      writeTextViaDomCopy('report text');
      const textarea = capturedSelections();
      assert.equal(textarea.length, 1);
      assert.equal(textarea[0].selected, 'report text');
      // The helper must not leave the throwaway textarea in the document.
      assert.equal(
        Array.from(document.querySelectorAll('textarea')).length,
        0,
        'throwaway textarea must be removed after copy',
      );
    } finally {
      restoreExec();
    }
  });

  function makeMemoryStore(): SnitchshotStorageLike & { store: Map<string, unknown> } {
    const store = new Map<string, unknown>();
    return {
      store,
      get: async (key) => ({ [key]: store.get(key) }),
      set: async (items) => {
        for (const [k, v] of Object.entries(items)) store.set(k, v);
      },
      remove: async (key) => {
        store.delete(key);
      },
    };
  }

  test('one report survives buffer → GET_SNITCHSHOT → COPY input unchanged', async () => {
    const storage = makeMemoryStore();
    const buffer = new SnitchshotBuffer(storage);
    const report = '# DEVSNITCHER REPORT\nline two';
    await buffer.fill(report, 7);

    const restoreExec = installExecCommand(() => true);
    let releaseRequested = false;
    try {
      // Boundary D — GET_SNITCHSHOT serves exactly what was filled (A/B/C).
      const served = (await buffer.peek())?.report ?? null;
      assert.equal(served, report);
      assert.equal(fingerprint(served), fingerprint(report));

      // Boundary F/G — the COPY release writes that very report to the copy
      // mechanism, unmodified.
      const outcome = await releaseReport(served, async () => {
        releaseRequested = true;
        return { ok: true };
      });
      assert.equal(outcome, 'released');

      const written = capturedSelections();
      assert.equal(written.length, 1);
      assert.equal(written[0].selected, report, 'clipboard writer receives the same report');
      assert.equal(fingerprint(written[0].selected), fingerprint(report));
      assert.equal(releaseRequested, true, 'a successful write authorizes the release request');
    } finally {
      restoreExec();
    }
  });

  test('clipboard writer failure sends no CLIPBOARD_RELEASED and keeps the SNITCHSHOT', async () => {
    const storage = makeMemoryStore();
    const buffer = new SnitchshotBuffer(storage);
    await buffer.fill('# KEEP ME', 2);

    const restoreExec = installExecCommand(() => false);
    let releaseRequested = false;
    try {
      await assert.rejects(
        releaseReport('# KEEP ME', async () => {
          releaseRequested = true;
          return { ok: true };
        }),
        /clipboard rejected/i,
      );
    } finally {
      restoreExec();
    }

    assert.equal(releaseRequested, false, 'a failed write must not send CLIPBOARD_RELEASED');
    assert.equal(await buffer.isOccupied(), true, 'the private SNITCHSHOT stays pending');
    assert.equal((await buffer.peek())?.report, '# KEEP ME');
  });

  test('an unconfirmed buffer clear keeps the pending state instead of a false release', async () => {
    const restoreExec = installExecCommand(() => true);
    try {
      const outcome = await releaseReport('report', async () => ({
        ok: false,
        error: 'Private SNITCHSHOT could not be cleared.',
      }));
      assert.equal(outcome, 'kept');
    } finally {
      restoreExec();
    }
  });

  test('sendReleased maps only a confirmed CLIPBOARD_CLEARED to ok', async () => {
    assert.deepEqual(await sendReleased(async () => ({ type: 'CLIPBOARD_CLEARED' })), { ok: true });

    const err = await sendReleased(async () => ({ type: 'EVIDENCE_ERROR', error: 'nope' }));
    assert.equal(err.ok, false);
    if (!err.ok) assert.equal(err.error, 'nope');

    const unknown = await sendReleased(async () => ({
      type: 'SNITCH_ERROR',
      error: 'other',
    }));
    assert.equal(unknown.ok, false);

    const empty = await sendReleased(async () => undefined);
    assert.equal(empty.ok, false);
  });
});

describe('popup CTA state render projection', () => {
  test('IDLE → SNITCH enabled; × hidden; no other action', () => {
    const cfg = ctaConfig('idle');
    assert.equal(cfg.snitchEnabled, true);
    assert.equal(cfg.closeVisible, false);
    assert.equal(cfg.copyEnabled, false);
    assert.equal(cfg.inputsEnabled, true);
    assert.equal(cfg.snitchLabel, 'Ready');
    assert.equal(cfg.copyLabel, 'No report');
  });

  test('OBSERVING → SNITCH unavailable; × visible and actionable; COPY unavailable', () => {
    const cfg = ctaConfig('observing');
    assert.equal(cfg.snitchEnabled, false);
    assert.equal(cfg.closeVisible, true, '× must be visible while acquisition is active');
    assert.equal(cfg.copyEnabled, false);
    assert.equal(cfg.inputsEnabled, false);
    assert.equal(cfg.snitchLabel, 'Watching…');
    assert.equal(cfg.copyLabel, 'Not ready');
  });

  test('SNITCHSHOT_PENDING → only COPY SNITCHSHOT enabled; × hidden', () => {
    const cfg = ctaConfig('snitchshot_pending');
    assert.equal(cfg.snitchEnabled, false);
    assert.equal(cfg.closeVisible, false);
    assert.equal(cfg.copyEnabled, true, 'a pending report must make COPY actionable');
    assert.equal(cfg.inputsEnabled, false);
    assert.equal(cfg.snitchLabel, 'Report pending');
    assert.equal(cfg.copyLabel, 'Send report to clipboard');
  });

  test('COPYING (local transition) → nothing actionable; COPY shows progress; × hidden', () => {
    const cfg = ctaConfig('copying');
    assert.equal(cfg.snitchEnabled, false);
    assert.equal(cfg.closeVisible, false);
    assert.equal(cfg.copyEnabled, false, 'double invocation must be prevented during copy');
    assert.equal(cfg.inputsEnabled, false);
    assert.equal(cfg.copyLabel, 'Copying…');
  });

  test('primary CTAs are never contradictory; × is the sole active control while acquiring', () => {
    for (const state of ['idle', 'observing', 'snitchshot_pending', 'copying'] as const) {
      const cfg = ctaConfig(state);
      const enabled = [cfg.snitchEnabled, cfg.copyEnabled].filter(Boolean).length;
      // Observing exposes only the × (not a primary CTA); COPYING locks all.
      const expected = state === 'observing' || state === 'copying' ? 0 : 1;
      assert.equal(enabled, expected, `state ${state} must enable exactly ${expected} primary CTA`);
      assert.equal(
        cfg.closeVisible,
        state === 'observing',
        `× must be visible ONLY during observing (state ${state})`,
      );
    }
  });
});
