import { invoke, isTauri } from "@tauri-apps/api/core";

export type PhpLineRuntime = {
  line: string;
  latestVersion: string | null;
  latestUrl: string | null;
  installedVersions: string[];
  activeVersion: string | null;
  fpmPort: number;
};

export type PhpCatalogResponse = {
  basePort: number;
  maxUploadSizeMb: string;
  memoryLimitMb: string;
  currentLine: string | null;
  laravelInstaller: {
    installed: boolean;
    version: string | null;
  };
  runtimes: PhpLineRuntime[];
};

export async function getPhpCatalog(): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_get_catalog");
}

export async function setPhpBasePort(basePort: number): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_set_base_port", { basePort });
}

export async function installLatestPhp(line: string): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_install_latest", { line });
}

export async function uninstallPhpLine(line: string): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_uninstall_line", { line });
}

export async function setActivePhp(line: string, version: string): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_set_active", { line, version });
}

export async function setPhpIniValues(
  maxUploadSizeMb: string,
  memoryLimitMb: string,
): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_set_ini_values", {
    maxUploadSizeMb,
    memoryLimitMb,
  });
}

export async function setPhpCurrentLine(line: string): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_set_current_line", { line });
}

export async function installOrUpdateLaravelInstaller(): Promise<PhpCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<PhpCatalogResponse>("php_install_laravel_installer");
}
