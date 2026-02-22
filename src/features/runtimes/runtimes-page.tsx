import { useEffect, useMemo, useState } from "react";
import { Check } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
  getPhpCatalog,
  installLatestPhp,
  setActivePhp,
  setPhpBasePort,
  setPhpCurrentLine,
  setPhpIniValues,
  uninstallPhpLine,
  type PhpCatalogResponse,
  type PhpLineRuntime,
} from "./php-api";

function errorMessage(err: unknown, fallback: string) {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "string" && err.trim().length > 0) return err;
  if (err && typeof err === "object" && "message" in err) {
    const msg = (err as { message?: unknown }).message;
    if (typeof msg === "string" && msg.trim().length > 0) return msg;
  }
  return fallback;
}

function latestLabel(runtime: PhpLineRuntime) {
  const installed = runtime.installedVersions[0];
  return installed ? `${runtime.line} (${installed})` : runtime.line;
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

export function RuntimesPage() {
  const [catalog, setCatalog] = useState<PhpCatalogResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [installingLine, setInstallingLine] = useState<string | null>(null);
  const [uninstallingLine, setUninstallingLine] = useState<string | null>(null);
  const [savingPort, setSavingPort] = useState(false);
  const [savingIni, setSavingIni] = useState(false);
  const [savingCurrent, setSavingCurrent] = useState(false);
  const [basePortInput, setBasePortInput] = useState("9000");
  const [maxUploadSizeMb, setMaxUploadSizeMb] = useState("128");
  const [memoryLimitMb, setMemoryLimitMb] = useState("512");
  const [currentLineInput, setCurrentLineInput] = useState("");

  const runtimes = useMemo(() => {
    const list = catalog?.runtimes ?? [];
    return [...list].sort((a, b) => Number(b.line) - Number(a.line));
  }, [catalog]);

  useEffect(() => {
    void refresh();
  }, []);

  async function refresh() {
    if (!catalog) {
      setLoading(true);
    }
    setError("");
    try {
      const response = await getPhpCatalog();
      setCatalog(response);
      setBasePortInput(String(response.basePort));
      setMaxUploadSizeMb(response.maxUploadSizeMb);
      setMemoryLimitMb(response.memoryLimitMb);
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, "Failed to load PHP catalog."));
    } finally {
      setLoading(false);
    }
  }

  async function handleInstall(line: string) {
    setInstallingLine(line);
    setError("");
    try {
      const response = await installLatestPhp(line);
      setCatalog(response);
    } catch (err) {
      setError(errorMessage(err, `Failed to install PHP ${line}.`));
    } finally {
      setInstallingLine(null);
    }
  }

  async function handleSetActive(line: string, version: string | null) {
    if (!version) return;
    setError("");
    try {
      const response = await setActivePhp(line, version);
      setCatalog(response);
    } catch (err) {
      setError(errorMessage(err, `Failed to set active PHP ${line}.`));
    }
  }

  async function handleUninstall(line: string) {
    setUninstallingLine(line);
    setError("");
    try {
      const response = await uninstallPhpLine(line);
      setCatalog(response);
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, `Failed to uninstall PHP ${line}.`));
    } finally {
      setUninstallingLine(null);
    }
  }

  async function handleSaveBasePort() {
    const parsed = Number(basePortInput);
    if (!Number.isInteger(parsed) || parsed < 1024 || parsed > 65000) {
      setError("Base port must be an integer between 1024 and 65000.");
      return;
    }
    setSavingPort(true);
    setError("");
    try {
      const response = await setPhpBasePort(parsed);
      setCatalog(response);
    } catch (err) {
      setError(errorMessage(err, "Failed to save base port."));
    } finally {
      setSavingPort(false);
    }
  }

  async function handleSaveCurrentLine() {
    if (!currentLineInput) return;
    setSavingCurrent(true);
    setError("");
    try {
      const response = await setPhpCurrentLine(currentLineInput);
      setCatalog(response);
      setCurrentLineInput(response.currentLine ?? "");
    } catch (err) {
      setError(errorMessage(err, "Failed to set current PHP line."));
    } finally {
      setSavingCurrent(false);
    }
  }

  const installedLines = runtimes.filter((runtime) => runtime.installedVersions.length > 0);

  async function handleSaveIniValues() {
    setSavingIni(true);
    setError("");
    try {
      const response = await setPhpIniValues(maxUploadSizeMb, memoryLimitMb);
      setCatalog(response);
      setMaxUploadSizeMb(response.maxUploadSizeMb);
      setMemoryLimitMb(response.memoryLimitMb);
    } catch (err) {
      setError(errorMessage(err, "Failed to save php.ini values."));
    } finally {
      setSavingIni(false);
    }
  }

  return (
    <div className="grid gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">PHP</h1>
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
                        {latestLabel(runtime)}
                        {catalog?.currentLine === runtime.line ? (
                          <Badge variant="outline" className="ml-2">
                            Current
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        {installedVersion ? (
                          <div className="flex items-center gap-2">
                            <Button
                              size="icon-xs"
                              variant="secondary"
                              onClick={() => void handleSetActive(runtime.line, installedVersion)}
                              aria-label={`set active PHP ${runtime.line}`}
                            >
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
                            onClick={() => void handleInstall(runtime.line)}
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
        <p className="text-sm text-muted-foreground">
          Select which installed PHP line should be linked as `current`.
        </p>
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
                PHP {runtime.line}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            onClick={() => void handleSaveCurrentLine()}
            disabled={savingCurrent || !currentLineInput}
          >
            {savingCurrent ? "Saving..." : "Set current"}
          </Button>
          <span className="text-sm text-muted-foreground">
            Active current: {catalog?.currentLine ? `PHP ${catalog.currentLine}` : "not set"}
          </span>
        </div>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Max File Upload Size</h3>
        <p className="text-sm text-muted-foreground">
          Configure the maximum file size that PHP will accept as file uploads (in MB).
        </p>
        <div className="flex items-center gap-2">
          <Input
            value={maxUploadSizeMb}
            onChange={(event) => setMaxUploadSizeMb(event.target.value)}
            className="max-w-44 bg-input"
          />
          <span className="text-sm text-muted-foreground">MB</span>
          <Button size="sm" variant="outline" onClick={() => void handleSaveIniValues()} disabled={savingIni}>
            {savingIni ? "Saving..." : "Save"}
          </Button>
        </div>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Memory Limit</h3>
        <p className="text-sm text-muted-foreground">
          Configure the maximum amount of memory your PHP scripts may consume (in MB).
        </p>
        <p className="text-sm text-muted-foreground">Use `-1` for unlimited.</p>
        <div className="flex items-center gap-2">
          <Input
            value={memoryLimitMb}
            onChange={(event) => setMemoryLimitMb(event.target.value)}
            className="max-w-44 bg-input"
          />
          <span className="text-sm text-muted-foreground">MB</span>
          <Button size="sm" variant="outline" onClick={() => void handleSaveIniValues()} disabled={savingIni}>
            {savingIni ? "Saving..." : "Save"}
          </Button>
        </div>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Laravel Installer</h3>
        <p className="text-sm text-muted-foreground">
          You are using the latest version of the Laravel Installer (5.24.6).
        </p>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="text-2xl font-semibold">Base Port</h3>
        <p className="text-sm text-muted-foreground">Configure the base port that PHP should use.</p>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            type="number"
            value={basePortInput}
            onChange={(event) => setBasePortInput(event.target.value)}
            className="max-w-32"
          />
          <Button onClick={handleSaveBasePort} disabled={savingPort}>
            {savingPort ? "Saving..." : "Save"}
          </Button>
          <span className="text-sm text-muted-foreground">Example: 9000 to 9074 for PHP 7.4</span>
        </div>
      </section>
    </div>
  );
}
