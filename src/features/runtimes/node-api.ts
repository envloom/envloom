import { invoke, isTauri } from "@tauri-apps/api/core";

export type NodeLineRuntime = {
  line: string;
  latestVersion: string | null;
  installedVersion: string | null;
  isCurrent: boolean;
};

export type NodeCatalogResponse = {
  nvmAvailable: boolean;
  error: string | null;
  currentVersion: string | null;
  installedVersions: string[];
  runtimes: NodeLineRuntime[];
};

export async function getNodeCatalog(): Promise<NodeCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<NodeCatalogResponse>("node_get_catalog");
}

export async function installNodeMajor(major: string): Promise<NodeCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<NodeCatalogResponse>("node_install_major", { major });
}

export async function setNodeCurrentVersion(version: string): Promise<NodeCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<NodeCatalogResponse>("node_set_current_version", { version });
}

export async function uninstallNodeVersion(version: string): Promise<NodeCatalogResponse> {
  if (!isTauri()) throw new Error("Tauri runtime not available");
  return invoke<NodeCatalogResponse>("node_uninstall_version", { version });
}
