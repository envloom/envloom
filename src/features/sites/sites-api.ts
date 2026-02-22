import { invoke, isTauri } from "@tauri-apps/api/core";

export type SiteRecord = {
  id: string;
  name: string;
  domain: string;
  linked: boolean;
  sslEnabled: boolean;
  path: string;
  phpVersion: string;
  nodeVersion: string;
  starterKit?: string | null;
};

export type SiteCreatePayload = {
  name: string;
  domain: string;
  linked: boolean;
  sslEnabled: boolean;
  path: string;
  phpVersion: string;
  nodeVersion: string;
  starterKit?: string | null;
};

export type SitePathInspection = {
  exists: boolean;
  isDirectory: boolean;
  suggestedName: string | null;
  framework: string;
  isPhpProject: boolean;
};

const fallbackSites: SiteRecord[] = [];

export async function listSites(): Promise<SiteRecord[]> {
  if (!isTauri()) return [...fallbackSites];
  return invoke<SiteRecord[]>("list_sites");
}

export async function createSite(payload: SiteCreatePayload): Promise<SiteRecord[]> {
  if (!isTauri()) {
    const id = `${payload.domain.replace(/\./g, "-")}-${Date.now()}`;
    fallbackSites.unshift({ id, ...payload });
    fallbackSites.sort((a, b) => a.domain.localeCompare(b.domain));
    return [...fallbackSites];
  }
  return invoke<SiteRecord[]>("create_site", { payload });
}

export async function deleteSite(siteId: string, deleteFiles: boolean): Promise<SiteRecord[]> {
  if (!isTauri()) {
    const idx = fallbackSites.findIndex((site) => site.id === siteId);
    if (idx >= 0) {
      fallbackSites.splice(idx, 1);
    }
    return [...fallbackSites];
  }
  return invoke<SiteRecord[]>("delete_site", {
    payload: { siteId, deleteFiles },
  });
}

export async function regenerateSiteSsl(siteId: string): Promise<SiteRecord[]> {
  if (!isTauri()) return [...fallbackSites];
  return invoke<SiteRecord[]>("site_regenerate_ssl", { siteId });
}

export async function setSiteSsl(siteId: string, sslEnabled: boolean): Promise<SiteRecord[]> {
  if (!isTauri()) {
    const target = fallbackSites.find((site) => site.id === siteId);
    if (target) target.sslEnabled = sslEnabled;
    return [...fallbackSites];
  }
  return invoke<SiteRecord[]>("site_set_ssl", { siteId, sslEnabled });
}

export async function setSitePhpVersion(siteId: string, phpVersion: string): Promise<SiteRecord[]> {
  if (!isTauri()) {
    const target = fallbackSites.find((site) => site.id === siteId);
    if (target) target.phpVersion = phpVersion;
    return [...fallbackSites];
  }
  return invoke<SiteRecord[]>("site_set_php_version", { siteId, phpVersion });
}

export async function pickExistingFolder(): Promise<string | null> {
  if (!isTauri()) return null;
  return invoke<string | null>("site_pick_existing_folder");
}

export async function inspectSitePath(path: string): Promise<SitePathInspection> {
  if (!isTauri()) {
    return {
      exists: false,
      isDirectory: false,
      suggestedName: null,
      framework: "unknown",
      isPhpProject: false,
    };
  }
  return invoke<SitePathInspection>("site_inspect_path", { path });
}
