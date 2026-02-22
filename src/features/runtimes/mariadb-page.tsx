import { useEffect, useMemo, useState } from "react";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  getMariaDbCatalog,
  installLatestMariaDb,
  setMariaDbCurrentLine,
  setMariaDbConfig,
  uninstallMariaDbLine,
  type MariaDbCatalogResponse,
} from "./mariadb-api";

function errorMessage(err: unknown, fallback: string) {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "string" && err.trim().length > 0) return err;
  if (err && typeof err === "object" && "message" in err) {
    const msg = (err as { message?: unknown }).message;
    if (typeof msg === "string" && msg.trim().length > 0) return msg;
  }
  return fallback;
}

function versionLabel(line: string, installedVersion: string | null) {
  if (installedVersion) return `${line} (${installedVersion})`;
  return line;
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

export function MariaDbPage() {
  const [catalog, setCatalog] = useState<MariaDbCatalogResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [installingLine, setInstallingLine] = useState<string | null>(null);
  const [uninstallingLine, setUninstallingLine] = useState<string | null>(null);
  const [savingConfig, setSavingConfig] = useState(false);
  const [savingCurrent, setSavingCurrent] = useState(false);
  const [portInput, setPortInput] = useState("3306");
  const [rootPasswordInput, setRootPasswordInput] = useState("");
  const [currentLineInput, setCurrentLineInput] = useState("");
  const [installPasswordDialogOpen, setInstallPasswordDialogOpen] = useState(false);
  const [pendingInstallLine, setPendingInstallLine] = useState<string | null>(null);
  const [installRootPasswordInput, setInstallRootPasswordInput] = useState("");

  const runtimes = useMemo(() => {
    const list = catalog?.runtimes ?? [];
    return [...list].sort((a, b) => Number(b.line) - Number(a.line));
  }, [catalog]);

  useEffect(() => {
    void refresh();
  }, []);

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const response = await getMariaDbCatalog();
      setCatalog(response);
      setPortInput(String(response.port));
      setRootPasswordInput(response.rootPassword ?? "");
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, "Failed to load MariaDB catalog."));
    } finally {
      setLoading(false);
    }
  }

  async function handleInstall(line: string, rootPasswordOverride?: string) {
    setInstallingLine(line);
    setError("");
    try {
      if (typeof rootPasswordOverride === "string") {
        const configResponse = await setMariaDbConfig(Number(portInput), rootPasswordOverride);
        setCatalog(configResponse);
        setPortInput(String(configResponse.port));
        setRootPasswordInput(configResponse.rootPassword ?? "");
        setCurrentLineInput(configResponse.currentLine ?? "");
      }
      const response = await installLatestMariaDb(line);
      setCatalog(response);
      setPortInput(String(response.port));
      setRootPasswordInput(response.rootPassword ?? "");
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, `Failed to install MariaDB ${line}.`));
    } finally {
      setInstallingLine(null);
    }
  }

  async function handleSavePortConfig() {
    const port = Number(portInput);
    if (!Number.isInteger(port) || port < 1024 || port > 65000) {
      setError("Port must be an integer between 1024 and 65000.");
      return;
    }
    setSavingConfig(true);
    setError("");
    try {
      const response = await setMariaDbConfig(port, rootPasswordInput);
      setCatalog(response);
      setPortInput(String(response.port));
      setRootPasswordInput(response.rootPassword ?? "");
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, "Failed to save MariaDB config."));
    } finally {
      setSavingConfig(false);
    }
  }

  async function handleSaveRootPassword() {
    const port = Number(portInput);
    if (!Number.isInteger(port) || port < 1024 || port > 65000) {
      setError("Port must be an integer between 1024 and 65000 before updating root password.");
      return;
    }
    setSavingConfig(true);
    setError("");
    try {
      const response = await setMariaDbConfig(port, rootPasswordInput);
      setCatalog(response);
      setPortInput(String(response.port));
      setRootPasswordInput(response.rootPassword ?? "");
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, "Failed to apply MariaDB root password."));
    } finally {
      setSavingConfig(false);
    }
  }

  function openInstallPasswordDialog(line: string) {
    setPendingInstallLine(line);
    setInstallRootPasswordInput(rootPasswordInput);
    setInstallPasswordDialogOpen(true);
  }

  async function confirmInstallWithPassword() {
    if (!pendingInstallLine) return;
    const line = pendingInstallLine;
    const password = installRootPasswordInput;
    setInstallPasswordDialogOpen(false);
    setPendingInstallLine(null);
    setRootPasswordInput(password);
    await handleInstall(line, password);
  }

  async function handleSetCurrentLine() {
    if (!currentLineInput) return;
    setSavingCurrent(true);
    setError("");
    try {
      const response = await setMariaDbCurrentLine(currentLineInput);
      setCatalog(response);
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, "Failed to set current MariaDB line."));
    } finally {
      setSavingCurrent(false);
    }
  }

  async function handleUninstall(line: string) {
    setUninstallingLine(line);
    setError("");
    try {
      const response = await uninstallMariaDbLine(line);
      setCatalog(response);
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, `Failed to uninstall MariaDB ${line}.`));
    } finally {
      setUninstallingLine(null);
    }
  }

  const installedLines = runtimes.filter((runtime) => runtime.installedVersions.length > 0);

  return (
    <div className="grid gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">MariaDB</h1>
      </div>
      <Separator />

      <section className="grid gap-3">
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
                  const installedVersion = runtime.installedVersions[0] ?? null;
                  const canUpdate = Boolean(installedVersion && isVersionNewer(runtime.latestVersion, installedVersion));
                  return (
                    <TableRow key={runtime.line}>
                      <TableCell className="font-medium">
                        {versionLabel(runtime.line, installedVersion)}
                        {catalog?.currentLine === runtime.line ? (
                          <Badge variant="outline" className="ml-2">
                            Current
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        {installedVersion ? (
                          <div className="flex items-center gap-2">
                            <Button size="icon-xs" variant="secondary" aria-label={`installed mariadb ${runtime.line}`}>
                              <Check className="size-3" />
                            </Button>
                            {canUpdate ? (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => void handleInstall(runtime.line)}
                                disabled={installingLine === runtime.line}
                              >
                                {installingLine === runtime.line ? "Updating..." : "Update"}
                              </Button>
                            ) : null}
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => void handleUninstall(runtime.line)}
                              disabled={
                                uninstallingLine === runtime.line ||
                                installingLine === runtime.line ||
                                catalog?.currentLine === runtime.line
                              }
                            >
                              {uninstallingLine === runtime.line ? "Uninstalling..." : "Uninstall"}
                            </Button>
                          </div>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => openInstallPasswordDialog(runtime.line)}
                            disabled={installingLine === runtime.line || !runtime.latestVersion}
                          >
                            {installingLine === runtime.line ? "Installing..." : "Install"}
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

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Current Version</h3>
        <p className="text-sm text-muted-foreground">Select which installed MariaDB major line is current.</p>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={currentLineInput}
            onChange={(event) => setCurrentLineInput(event.target.value)}
            className="h-9 min-w-40 rounded-md border border-input bg-input px-3 text-sm"
          >
            <option value="" disabled>
              Select installed line
            </option>
            {installedLines.map((runtime) => (
              <option key={runtime.line} value={runtime.line}>
                MariaDB {runtime.line}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            onClick={() => void handleSetCurrentLine()}
            disabled={savingCurrent || !currentLineInput}
          >
            {savingCurrent ? "Saving..." : "Set current"}
          </Button>
          <span className="text-sm text-muted-foreground">
            Current: {catalog?.currentLine ? `MariaDB ${catalog.currentLine}` : "not set"}
          </span>
        </div>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Port</h3>
        <p className="text-sm text-muted-foreground">Configure the MariaDB port.</p>
        <div className="flex items-center gap-2">
          <Input
            type="number"
            value={portInput}
            onChange={(event) => setPortInput(event.target.value)}
            className="max-w-32"
          />
          <Button size="sm" variant="outline" onClick={() => void handleSavePortConfig()} disabled={savingConfig}>
            {savingConfig ? "Saving..." : "Save port"}
          </Button>
        </div>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Root Password</h3>
        <p className="text-sm text-muted-foreground">Set root password used in generated client config.</p>
        <div className="flex items-center gap-2">
          <Input
            type="password"
            value={rootPasswordInput}
            onChange={(event) => setRootPasswordInput(event.target.value)}
            className="max-w-80 bg-input"
          />
          <Button size="sm" variant="outline" onClick={() => void handleSaveRootPassword()} disabled={savingConfig}>
            {savingConfig ? "Saving..." : "Apply password"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Applies the password to MariaDB if it is running, and updates generated client config.
        </p>
      </section>

      <Dialog open={installPasswordDialogOpen} onOpenChange={setInstallPasswordDialogOpen}>
        <DialogContent className="max-w-md!">
          <DialogHeader>
            <DialogTitle>Set Root Password Before Install</DialogTitle>
            <DialogDescription>
              MariaDB {pendingInstallLine ? ` ${pendingInstallLine}` : ""} will be installed using this root password.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="mariadb-install-root-password">
              Root password
            </label>
            <Input
              id="mariadb-install-root-password"
              type="password"
              value={installRootPasswordInput}
              onChange={(event) => setInstallRootPasswordInput(event.target.value)}
              className="bg-input"
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setInstallPasswordDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => void confirmInstallWithPassword()}
              disabled={!pendingInstallLine || installingLine !== null}
            >
              Install MariaDB
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
