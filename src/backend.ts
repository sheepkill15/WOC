import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type BackendKind = "tauri" | "agent";
export type BackendConnection = { kind: BackendKind; running: boolean };

const isTauri = "__TAURI_INTERNALS__" in window;
const agentUrl = (import.meta.env.VITE_CLEANER_AGENT_URL as string | undefined)?.replace(/\/$/, "")
  ?? "http://127.0.0.1:47653";
const routes: Record<string, { path: string; method: "GET" | "POST" }> = {
  installed_applications: { path: "/api/installed-applications", method: "GET" },
  load_latest_scan: { path: "/api/latest-scan", method: "GET" },
  load_history_report: { path: "/api/history-report", method: "GET" },
  public_data_status: { path: "/api/public-data/status", method: "GET" },
  update_public_data: { path: "/api/public-data/update", method: "POST" },
  export_diagnostics: { path: "/api/diagnostics/export", method: "POST" },
  start_scan: { path: "/api/scan/start", method: "POST" },
  cancel_scan: { path: "/api/scan/cancel", method: "POST" },
};

let activeKind: BackendKind | null = null;
let eventSource: EventSource | null = null;
let eventListenerCount = 0;

async function agentRequest<T>(command: string): Promise<T> {
  const route = routes[command];
  if (!route) throw new Error(`Unsupported cleaner-agent command: ${command}`);
  const response = await fetch(`${agentUrl}${route.path}`, {
    method: route.method,
    cache: "no-store",
    headers: route.method === "POST" ? { "X-Orphan-Cleaner-Client": "web-v1" } : undefined,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { error?: string } | null;
    throw new Error(body?.error ?? `Cleaner agent returned HTTP ${response.status}`);
  }
  return await response.json() as T;
}

export async function connectBackend(): Promise<BackendConnection> {
  if (isTauri) {
    activeKind = "tauri";
    return { kind: "tauri", running: false };
  }
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 1800);
  try {
    const response = await fetch(`${agentUrl}/api/health`, { cache: "no-store", signal: controller.signal });
    if (!response.ok) throw new Error(`Cleaner agent returned HTTP ${response.status}`);
    const health = await response.json() as { service?: string; transportVersion?: number; running?: boolean };
    if (health.service !== "windows-orphan-cleaner-agent" || health.transportVersion !== 1) {
      throw new Error("An incompatible service is using the cleaner-agent address");
    }
    activeKind = "agent";
    return { kind: "agent", running: Boolean(health.running) };
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function invokeBackend<T>(command: string): Promise<T> {
  if (activeKind === "tauri") return await invoke<T>(command);
  if (activeKind === "agent") return await agentRequest<T>(command);
  throw new Error("No Windows cleaner backend is connected");
}

export async function listenBackend<T>(eventName: string, callback: (payload: T) => void): Promise<UnlistenFn> {
  if (activeKind === "tauri") {
    return await listen<T>(eventName, event => callback(event.payload));
  }
  if (activeKind !== "agent") throw new Error("No Windows cleaner backend is connected");
  if (!eventSource) eventSource = new EventSource(`${agentUrl}/api/events`);
  const source = eventSource;
  const handler = (event: Event) => {
    const message = event as MessageEvent<string>;
    callback(JSON.parse(message.data) as T);
  };
  source.addEventListener(eventName, handler);
  eventListenerCount++;
  return () => {
    source.removeEventListener(eventName, handler);
    eventListenerCount--;
    if (eventListenerCount === 0 && eventSource === source) {
      source.close();
      eventSource = null;
    }
  };
}

export function disconnectBackend(): void {
  activeKind = null;
  eventListenerCount = 0;
  eventSource?.close();
  eventSource = null;
}
