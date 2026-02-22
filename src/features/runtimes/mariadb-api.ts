import { invoke, isTauri } from "@tauri-apps/api/core";

export type MariaDbLineRuntime = {
  line: string;
  latestVersion: string | null;
  installedVersions: string[];
};

export type MariaDbCatalogResponse = {
  port: number;
  rootPassword: string;
  currentLine: string | null;
  runtimes: MariaDbLineRuntime[];
};

export async function getMariaDbCatalog(): Promise<MariaDbCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<MariaDbCatalogResponse>("mariadb_get_catalog");
}

export async function installLatestMariaDb(line: string): Promise<MariaDbCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<MariaDbCatalogResponse>("mariadb_install_latest", { line });
}

export async function uninstallMariaDbLine(line: string): Promise<MariaDbCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<MariaDbCatalogResponse>("mariadb_uninstall_line", { line });
}

export async function setMariaDbConfig(
  port: number,
  rootPassword: string,
): Promise<MariaDbCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<MariaDbCatalogResponse>("mariadb_set_config", { port, rootPassword });
}

export async function setMariaDbCurrentLine(line: string): Promise<MariaDbCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<MariaDbCatalogResponse>("mariadb_set_current_line", { line });
}
