import { invoke, isTauri } from "@tauri-apps/api/core";

export type AppSettingsResponse = {
  autoStartServices: boolean;
  autoUpdate: boolean;
  configPath: string;
};

export async function getAppSettings(): Promise<AppSettingsResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<AppSettingsResponse>("settings_get");
}

export async function setAppSettings(autoStartServices: boolean, autoUpdate: boolean): Promise<AppSettingsResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<AppSettingsResponse>("settings_set", { autoStartServices, autoUpdate });
}
