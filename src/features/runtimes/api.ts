import { invoke, isTauri } from "@tauri-apps/api/core";

export type RuntimeItem = {
  runtime: string;
  active: string;
  installed: string[];
};

export async function listRuntimes(): Promise<RuntimeItem[]> {
  if (!isTauri()) return [];
  return invoke<RuntimeItem[]>("list_runtimes");
}

export async function setActiveRuntime(runtime: string, version: string): Promise<RuntimeItem[]> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<RuntimeItem[]>("set_active_runtime", { runtime, version });
}

export async function addRuntimeVersion(runtime: string, version: string): Promise<RuntimeItem[]> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<RuntimeItem[]>("add_runtime_version", { runtime, version });
}

export async function removeRuntimeVersion(runtime: string, version: string): Promise<RuntimeItem[]> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<RuntimeItem[]>("remove_runtime_version", { runtime, version });
}
