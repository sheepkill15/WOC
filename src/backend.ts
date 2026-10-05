import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type BackendKind = "tauri" | "agent";
export type BackendConnection = { kind: BackendKind; running: boolean };

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
const agentUrl = (import.meta.env.VITE_CLEANER_AGENT_URL as string | undefined)?.replace(/\/$/, "")
  ?? "http://127.0.0.1:47653";
const TRANSPORT_VERSION = 3;

let activeKind: BackendKind | null = null;
let eventSource: EventSource | null = null;
let eventListenerCount = 0;

async function agentRequest<T>(command: string, args?: unknown): Promise<T> {
  const response = await fetch(`${agentUrl}/api/invoke/${encodeURIComponent(command)}`, {
    method: "POST",
    cache: "no-store",
    headers: { "X-Orphan-Cleaner-Client": "web-v3", "Content-Type": "application/json" },
    body: JSON.stringify(args ?? {}),
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
    const info = await invoke<{ running: boolean }>("backend", { command: "app_info", args: null });
    return { kind: "tauri", running: Boolean(info.running) };
  }
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 1800);
  try {
    const response = await fetch(`${agentUrl}/api/health`, { cache: "no-store", signal: controller.signal });
    if (!response.ok) throw new Error(`Cleaner agent returned HTTP ${response.status}`);
    const health = await response.json() as { service?: string; transportVersion?: number; running?: boolean };
    if (health.service !== "windows-orphan-cleaner-agent") throw new Error("An unrelated service is using the cleaner-agent address");
    if (health.transportVersion !== TRANSPORT_VERSION) throw new Error("The running cleaner agent is a different version. Restart it with `npm run agent`.");
    activeKind = "agent";
    return { kind: "agent", running: Boolean(health.running) };
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (activeKind === "tauri") return await invoke<T>("backend", { command, args: args ?? null });
  if (activeKind === "agent") return await agentRequest<T>(command, args);
  throw new Error("No Windows cleaner backend is connected");
}

export async function listenBackend<T>(eventName: string, callback: (payload: T) => void): Promise<UnlistenFn> {
  if (activeKind === "tauri") return await listen<T>(eventName, event => callback(event.payload));
  if (activeKind !== "agent") throw new Error("No Windows cleaner backend is connected");
  if (!eventSource) eventSource = new EventSource(`${agentUrl}/api/events`);
  const source = eventSource;
  const nativeEvent = eventName === "backend-reconnected" ? "open" : eventName;
  const handler = (event: Event) => callback((nativeEvent === "open" ? {} : JSON.parse((event as MessageEvent<string>).data)) as T);
  source.addEventListener(nativeEvent, handler);
  eventListenerCount++;
  return () => {
    source.removeEventListener(nativeEvent, handler);
    eventListenerCount--;
    if (eventListenerCount === 0 && eventSource === source) { source.close(); eventSource = null; }
  };
}

export function disconnectBackend(): void {
  activeKind = null;
  eventListenerCount = 0;
  eventSource?.close();
  eventSource = null;
}
