/** The page talks only to its host-bound instance; no executable, host ID or credential API is exposed. */
export interface Transport {
  postMessage(message: unknown): void;
  subscribe(listener: (message: unknown) => void): () => void;
}

export interface Theme {
  mode: "light" | "dark";
  fontFamily: string;
  fontSize: number;
  density: "compact" | "comfortable";
  language: string;
  reducedMotion: boolean;
  colors: Record<string, string>;
}

type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> };

/** Unknown write results remain distinct from cancelled reads; clients must reconcile with the supplied operation ID. */
export class PluginError extends Error {
  code: string;
  operationId?: string;
  constructor(code: string, message: string, operationId?: string) {
    super(message);
    this.name = "PluginError";
    this.code = code;
    this.operationId = operationId;
  }
}

/** One client owns bounded pending callbacks and can be disposed without claiming backend work was cancelled. */
export class PluginClient {
  private transport: Transport;
  private unsubscribe: () => void;
  private pending = new Map<number, Pending>();
  private listeners = new Map<string, Set<(value: unknown) => void>>();
  private nextId = 1;
  private disposed = false;

  constructor(transport: Transport) {
    this.transport = transport;
    this.unsubscribe = transport.subscribe(message => this.receive(message));
  }

  /** Only declared command identities are submitted; the host captures the source and rechecks capabilities. */
  invoke(command: string, payload: unknown = {}): Promise<unknown> {
    return this.request("command.invoke", { command, payload });
  }

  /** Querying an operation never repeats it, including after a page reload or backend restart. */
  operationStatus(operationId: string): Promise<unknown> {
    return this.request("operation.query", { operation_id: operationId });
  }

  /** State belongs to this view, so changing tabs does not change the storage target. */
  readState(): Promise<unknown> { return this.request("view.state.read", {}); }

  /** The host validates size/version and persists through its existing workspace transaction. */
  saveState(value: unknown): Promise<unknown> { return this.request("view.state.write", { value }); }

  /** Cancellation is represented separately from an empty path and leaves the previous field value intact. */
  selectPath(options: { directory?: boolean; multiple?: boolean }): Promise<unknown> {
    return this.request("ui.path.select", options);
  }

  /** The host owns focus, wording placement and modal occupancy; a page cannot open a top-level window. */
  confirm(options: { id: string; title: string; message: string; danger?: boolean }): Promise<unknown> {
    return this.request("ui.confirm", options);
  }

  /** Field/page errors should stay inline; notifications are reserved for short success feedback. */
  notify(message: string): Promise<unknown> { return this.request("ui.notify", { message }); }

  /** A returned disposer prevents hidden or destroyed pages from retaining subscriptions. */
  on(event: string, listener: (value: unknown) => void): () => void {
    if (this.disposed) throw new PluginError("disposed", "Plugin view has closed");
    if (this.listeners.size >= 64 && !this.listeners.has(event)) throw new PluginError("limit", "Too many event subscriptions");
    const group = this.listeners.get(event) ?? new Set();
    if (group.size >= 64) throw new PluginError("limit", "Too many event subscribers");
    group.add(listener);
    this.listeners.set(event, group);
    return () => { group.delete(listener); if (!group.size) this.listeners.delete(event); };
  }

  /** Disposing only detaches UI receipts; it deliberately does not claim to cancel submitted backend writes. */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.unsubscribe();
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new PluginError("view_closed", "View closed; submitted operations may still be running"));
    }
    this.pending.clear();
    this.listeners.clear();
  }

  /** Bounded requests fail locally before sending; UI timeouts never retry an operation. */
  private request(method: string, params: unknown): Promise<unknown> {
    if (this.disposed) return Promise.reject(new PluginError("disposed", "Plugin view has closed"));
    if (this.pending.size >= 32) return Promise.reject(new PluginError("busy", "Too many pending requests"));
    const id = this.nextId++;
    const message = { version: 1, id, method, params };
    let encoded: string;
    try { encoded = JSON.stringify(message); }
    catch { return Promise.reject(new PluginError("invalid", "Request must be serializable")); }
    if (new TextEncoder().encode(encoded).length > 60 * 1024) return Promise.reject(new PluginError("limit", "Request exceeds bridge limit"));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new PluginError("receipt_unknown", "No host receipt; check operation status before retrying"));
      }, 65000);
      this.pending.set(id, { resolve, reject, timer });
      try { this.transport.postMessage(message); }
      catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new PluginError("transport", "Host bridge unavailable"));
      }
    });
  }

  /** Unknown and late IDs are ignored instead of completing a newer request; event failures stay local. */
  private receive(message: unknown): void {
    if (this.disposed || !message || typeof message !== "object") return;
    const envelope = message as Record<string, unknown>;
    if (envelope.version !== 1) return;
    if (typeof envelope.event === "string") {
      for (const listener of this.listeners.get(envelope.event) ?? []) {
        try { listener(envelope.payload); } catch { /* A broken subscriber cannot block other consumers. */ }
      }
      return;
    }
    if (typeof envelope.id !== "number") return;
    const pending = this.pending.get(envelope.id);
    if (!pending) return;
    const hasResult = Object.hasOwn(envelope, "result");
    const hasError = Object.hasOwn(envelope, "error");
    if (hasResult === hasError) return;
    this.pending.delete(envelope.id);
    clearTimeout(pending.timer);
    if (hasError) {
      const error = envelope.error as Record<string, unknown> | null;
      pending.reject(new PluginError(typeof error?.code === "string" ? error.code : "host_error", typeof error?.message === "string" ? error.message : "Host request failed", typeof error?.operation_id === "string" ? error.operation_id : undefined));
    } else { pending.resolve(envelope.result); }
  }
}

/** Bind only to the host-injected bridge; ordinary browsers fail explicitly rather than opening localhost. */
export function connect(): PluginClient {
  const bridge = (globalThis as unknown as { kerminalHost?: { postMessage(message: unknown): void } }).kerminalHost;
  if (!bridge) throw new PluginError("unavailable", "Kerminal host bridge is unavailable");
  return new PluginClient({
    postMessage: message => bridge.postMessage(message),
    subscribe: listener => {
      const handler = (event: Event) => listener((event as CustomEvent).detail);
      globalThis.addEventListener("kerminal:message", handler);
      return () => globalThis.removeEventListener("kerminal:message", handler);
    },
  });
}

/** Shared CSS variables keep plugin typography and density aligned without giving pages control over the host. */
export function applyTheme(theme: Theme, root: HTMLElement = document.documentElement): void {
  root.dataset.theme = theme.mode;
  root.dataset.density = theme.density;
  root.lang = theme.language;
  root.style.colorScheme = theme.mode;
  root.style.setProperty("--kerminal-font-family", theme.fontFamily);
  root.style.setProperty("--kerminal-font-size", `${Math.max(10, Math.min(24, theme.fontSize))}px`);
  root.style.setProperty("--kerminal-motion-duration", theme.reducedMotion ? "0ms" : "120ms");
  for (const [name, color] of Object.entries(theme.colors)) {
    if (/^[a-z][a-z0-9-]*$/.test(name)) root.style.setProperty(`--kerminal-${name}`, color);
  }
}
