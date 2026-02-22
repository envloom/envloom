import { useEffect, useMemo, useState } from "react";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  getNodeCatalog,
  installNodeMajor,
  setNodeCurrentVersion,
  uninstallNodeVersion,
  type NodeCatalogResponse,
} from "./node-api";

function versionLabel(line: string, installedVersion: string | null) {
  if (installedVersion) return installedVersion;
  return `${line}.x`;
}

function errorMessage(err: unknown, fallback: string) {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "string" && err.trim().length > 0) return err;
  if (err && typeof err === "object" && "message" in err) {
    const msg = (err as { message?: unknown }).message;
    if (typeof msg === "string" && msg.trim().length > 0) return msg;
  }
  return fallback;
}

function isVersionNewer(latest: string | null | undefined, installed: string | null | undefined) {
  if (!latest || !installed) return false;
  const a = latest.split(".").map((part) => Number(part) || 0);
  const b = installed.split(".").map((part) => Number(part) || 0);
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i += 1) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av > bv) return true;
    if (av < bv) return false;
  }
  return false;
}

export function NodePage() {
  const [catalog, setCatalog] = useState<NodeCatalogResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [installingMajor, setInstallingMajor] = useState<string | null>(null);
  const [uninstallingVersion, setUninstallingVersion] = useState<string | null>(null);
  const [settingCurrent, setSettingCurrent] = useState(false);
  const [currentVersionInput, setCurrentVersionInput] = useState("");

  const runtimes = useMemo(() => catalog?.runtimes ?? [], [catalog]);

  useEffect(() => {
    void refresh();
  }, []);

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const response = await getNodeCatalog();
      setCatalog(response);
      setCurrentVersionInput(response.currentVersion ?? "");
      if (response.error) setError(response.error);
    } catch (err) {
      setError(errorMessage(err, "Failed to load Node catalog."));
    } finally {
      setLoading(false);
    }
  }

  async function handleInstall(major: string) {
    setInstallingMajor(major);
    setError("");
    try {
      const response = await installNodeMajor(major);
      setCatalog(response);
      setCurrentVersionInput(response.currentVersion ?? "");
      if (response.error) setError(response.error);
    } catch (err) {
      setError(errorMessage(err, `Failed to install Node ${major}.x`));
    } finally {
      setInstallingMajor(null);
    }
  }

  async function handleSetCurrent() {
    if (!currentVersionInput) return;
    setSettingCurrent(true);
    setError("");
    try {
      const response = await setNodeCurrentVersion(currentVersionInput);
      setCatalog(response);
      setCurrentVersionInput(response.currentVersion ?? "");
      if (response.error) setError(response.error);
    } catch (err) {
      setError(errorMessage(err, "Failed to set current Node version."));
    } finally {
      setSettingCurrent(false);
    }
  }

  async function handleUninstall(version: string) {
    setUninstallingVersion(version);
    setError("");
    try {
      const response = await uninstallNodeVersion(version);
      setCatalog(response);
      setCurrentVersionInput(response.currentVersion ?? "");
      if (response.error) setError(response.error);
    } catch (err) {
      setError(errorMessage(err, `Failed to uninstall Node ${version}.`));
    } finally {
      setUninstallingVersion(null);
    }
  }

  return (
    <div className="grid gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Node</h1>
      </div>
      <Separator />

      <section className="grid gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={currentVersionInput}
            onChange={(event) => setCurrentVersionInput(event.target.value)}
            className="h-9 min-w-40 rounded-md border border-input bg-input px-3 text-sm"
          >
            <option value="" disabled>
              Select installed version
            </option>
            {(catalog?.installedVersions ?? []).map((version) => (
              <option key={version} value={version}>
                {version}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            onClick={() => void handleSetCurrent()}
            disabled={settingCurrent || !currentVersionInput || !catalog?.nvmAvailable}
          >
            {settingCurrent ? "Saving..." : "Set current"}
          </Button>
          <span className="text-sm text-muted-foreground">
            Current: {catalog?.currentVersion ?? "not set"}
          </span>
        </div>
        <h2 className="text-xl font-semibold">Versions</h2>
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[20%]">Version</TableHead>
                <TableHead className="w-[80%]">Installed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={2} className="text-center text-muted-foreground">
                    Loading versions...
                  </TableCell>
                </TableRow>
              ) : null}
              {!loading &&
                runtimes.map((runtime) => {
                  const installed = Boolean(runtime.installedVersion);
                  const canUpdate = Boolean(
                    runtime.installedVersion && isVersionNewer(runtime.latestVersion, runtime.installedVersion),
                  );
                  return (
                    <TableRow key={runtime.line}>
                      <TableCell className="font-medium">
                        {versionLabel(runtime.line, runtime.installedVersion)}
                        {runtime.isCurrent ? (
                          <Badge variant="outline" className="ml-2">
                            Current
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        {installed ? (
                          <div className="flex items-center gap-2">
                            <Button size="icon-xs" variant="secondary" aria-label={`installed node ${runtime.line}`}>
                              <Check className="size-3" />
                            </Button>
                            {canUpdate ? (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => void handleInstall(runtime.line)}
                                disabled={installingMajor === runtime.line || !catalog?.nvmAvailable}
                              >
                                {installingMajor === runtime.line ? "Updating..." : "Update"}
                              </Button>
                            ) : null}
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => void handleUninstall(runtime.installedVersion ?? "")}
                              disabled={
                                !runtime.installedVersion ||
                                installingMajor === runtime.line ||
                                uninstallingVersion === runtime.installedVersion ||
                                runtime.isCurrent
                              }
                            >
                              {uninstallingVersion === runtime.installedVersion ? "Uninstalling..." : "Uninstall"}
                            </Button>
                          </div>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void handleInstall(runtime.line)}
                            disabled={installingMajor === runtime.line || !catalog?.nvmAvailable}
                          >
                            {installingMajor === runtime.line ? "Installing..." : "Install"}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
            </TableBody>
          </Table>
        </div>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
      </section>
    </div>
  );
}
