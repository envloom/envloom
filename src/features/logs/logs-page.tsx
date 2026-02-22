import { useEffect, useMemo, useState } from "react";
import { LazyLog } from "@melloware/react-logviewer";
import { Button } from "@/components/ui/button";
import { getPhpCatalog } from "@/features/runtimes/php-api";
import { listLogFiles, readLogFile, type LogFileItem } from "./logs-api";

function toErrorMessage(error: unknown, fallback: string) {
  if (typeof error === "string" && error.trim()) return error;
  if (error instanceof Error && error.message.trim()) return error.message;
  return fallback;
}

function parsePhpLineFromLabel(label: string) {
  const lower = label.toLowerCase();
  const match = lower.match(/^php-([0-9]+)_([0-9]+)\.error\.log$/);
  if (!match) return null;
  return `${match[1]}.${match[2]}`;
}

export function LogsPage() {
  const [files, setFiles] = useState<LogFileItem[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(true);
  const [lines, setLines] = useState<string[]>([]);
  const [nginxAccessLines, setNginxAccessLines] = useState<string[]>([]);
  const [nginxErrorLines, setNginxErrorLines] = useState<string[]>([]);
  const [loadingContent, setLoadingContent] = useState(false);
  const [error, setError] = useState("");
  const [service, setService] = useState<"runtime" | "nginx" | "mysql" | "php">("runtime");
  const [nginxScope, setNginxScope] = useState("general");
  const [selectedId, setSelectedId] = useState("");
  const [phpScope, setPhpScope] = useState("current");
  const [phpCurrentLine, setPhpCurrentLine] = useState<string | null>(null);

  const runtimeFiles = useMemo(
    () => files.filter((file) => file.category === "runtime"),
    [files],
  );
  const nginxSiteFiles = useMemo(
    () => files.filter((file) => file.category === "site" && file.relativePath.startsWith("nginx/sites/")),
    [files],
  );
  const mysqlFiles = useMemo(
    () => files.filter((file) => file.category === "binary" && file.group.toLowerCase() === "mariadb"),
    [files],
  );
  const phpFiles = useMemo(
    () => files.filter((file) => file.category === "binary" && file.group.toLowerCase() === "php"),
    [files],
  );

  const nginxSites = useMemo(() => {
    const values = new Set<string>();
    for (const file of nginxSiteFiles) {
      const name = file.label.toLowerCase();
      const site =
        name.endsWith(".access.log")
          ? name.slice(0, -".access.log".length)
          : name.endsWith(".error.log")
            ? name.slice(0, -".error.log".length)
            : "";
      if (site) values.add(site);
    }
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [nginxSiteFiles]);

  const phpVersions = useMemo(() => {
    const values = new Set<string>();
    for (const file of phpFiles) {
      const line = parsePhpLineFromLabel(file.label);
      if (line) values.add(line);
    }
    return Array.from(values).sort((a, b) => (Number(b) || 0) - (Number(a) || 0));
  }, [phpFiles]);

  const selected = useMemo(
    () => files.find((file) => file.id === selectedId) ?? null,
    [files, selectedId],
  );

  const filteredLines = lines;
  const filteredNginxAccessLines = nginxAccessLines;
  const filteredNginxErrorLines = nginxErrorLines;

  async function refreshFiles() {
    setLoadingFiles(true);
    setError("");
    try {
      const [rows, phpCatalog] = await Promise.all([listLogFiles(), getPhpCatalog().catch(() => null)]);
      setFiles(rows);
      setPhpCurrentLine(phpCatalog?.currentLine ?? null);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to load log files."));
      setFiles([]);
      setSelectedId("");
    } finally {
      setLoadingFiles(false);
    }
  }

  async function refreshContent() {
    setLoadingContent(true);
    setError("");
    try {
      if (service === "nginx") {
        const base =
          nginxScope === "general"
            ? "nginx"
            : `nginx/sites/${nginxScope}`;
        const [accessLines, errorLines] = await Promise.all([
          readLogFile(`${base}.access.log`, 500).catch(() => []),
          readLogFile(`${base}.error.log`, 500).catch(() => []),
        ]);
        setNginxAccessLines(accessLines);
        setNginxErrorLines(errorLines);
        setLines([]);
        return;
      }

      const pool =
        service === "runtime" ? runtimeFiles : service === "mysql" ? mysqlFiles : phpFiles;
      const target =
        pool.find((file) => file.id === selectedId) ??
        pool[0] ??
        null;
      if (!target) {
        setLines([]);
        setNginxAccessLines([]);
        setNginxErrorLines([]);
        return;
      }
      const nextLines = await readLogFile(target.relativePath, 800);
      setLines(nextLines);
      setNginxAccessLines([]);
      setNginxErrorLines([]);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to read selected log file."));
      setLines([]);
      setNginxAccessLines([]);
      setNginxErrorLines([]);
    } finally {
      setLoadingContent(false);
    }
  }

  useEffect(() => {
    void refreshFiles();
  }, []);

  useEffect(() => {
    if (service !== "nginx") return;
    if (nginxScope !== "general") return;
    return;
  }, [service, nginxScope]);

  useEffect(() => {
    if (service === "runtime") {
      setSelectedId(runtimeFiles[0]?.id ?? "");
      return;
    }
    if (service === "mysql") {
      setSelectedId(mysqlFiles[0]?.id ?? "");
      return;
    }
    if (service === "php") {
      if (phpScope === "current" && phpCurrentLine) {
        const match = phpFiles.find((file) => parsePhpLineFromLabel(file.label) === phpCurrentLine);
        setSelectedId(match?.id ?? phpFiles[0]?.id ?? "");
        return;
      }
      const match = phpFiles.find((file) => parsePhpLineFromLabel(file.label) === phpScope);
      setSelectedId(match?.id ?? phpFiles[0]?.id ?? "");
      return;
    }
    if (service === "nginx") {
      if (nginxScope === "general") {
        return;
      }
      const site = nginxSites.find((value) => value === nginxScope);
      if (!site) {
        setNginxScope("general");
      }
    }
  }, [
    service,
    runtimeFiles,
    mysqlFiles,
    phpFiles,
    phpScope,
    phpCurrentLine,
    nginxScope,
    nginxSites,
  ]);

  useEffect(() => {
    if (service !== "nginx") {
      void refreshContent();
      return;
    }
    if (nginxScope === "general" || nginxSites.includes(nginxScope)) {
      void refreshContent();
    }
  }, [service, selectedId, nginxScope, nginxSites.length]);

  function ServiceTab({
    value,
    label,
  }: {
    value: "runtime" | "php" | "nginx" | "mysql";
    label: string;
  }) {
    const active = service === value;
    return (
      <button
        type="button"
        onClick={() => setService(value)}
        className={[
          "h-8 rounded-md border px-3 text-xs font-medium transition-colors",
          active
            ? "border-emerald-400/70 bg-emerald-500/15 text-emerald-300"
            : "border-input bg-background/70 text-foreground hover:bg-muted/60",
        ].join(" ")}
      >
        {label}
      </button>
    );
  }

  function LogPanel({
    title,
    panelLines,
    viewerHeight = 260,
  }: {
    title: string;
    panelLines: string[];
    viewerHeight?: number;
  }) {
    return (
      <div className="grid h-full min-h-0 grid-rows-[auto_1fr] gap-2">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-medium text-muted-foreground">{title}</p>
          <p className="text-[11px] text-muted-foreground">{panelLines.length} lines</p>
        </div>
        <div className="h-full min-h-0 rounded-xl border bg-background/80 p-3 font-mono text-xs leading-5">
          {loadingContent ? (
            <span className="text-muted-foreground">Loading...</span>
          ) : panelLines.length === 0 ? (
            <span className="text-muted-foreground">No lines for this selection/filter.</span>
          ) : (
            <div className="h-full min-h-55 overflow-hidden rounded-md">
              <LazyLog
                text={panelLines.join("\n")}
                height={viewerHeight}
                width="100%"
                follow
                enableSearch={false}
                enableHotKeys={false}
                enableLineNumbers
                enableGutters={false}
                selectableLines
                wrapLines
                rowHeight={20}
                overscanRowCount={50}
                style={{
                  fontFamily:
                    "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace",
                  fontSize: 12,
                  lineHeight: "1.4",
                  backgroundColor: "transparent",
                }}
                containerStyle={{
                  background: "transparent",
                }}
              />
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="grid h-full min-h-0 gap-4">
      <section className="grid min-h-0 gap-3">
        <div className="border-b px-5 py-4">
          <h1 className="text-2xl font-semibold tracking-tight">LOGS</h1>
        </div>

        <div className="grid min-h-0 grid-rows-[auto_auto_1fr] gap-4 p-5">
          <div className="flex flex-wrap items-center gap-2">
            <ServiceTab value="runtime" label="Runtime" />
            <ServiceTab value="php" label="PHP" />
            <ServiceTab value="nginx" label="Nginx" />
            <ServiceTab value="mysql" label="MySql" />

            <div className="ml-auto flex flex-wrap items-center gap-2">
              {service === "nginx" ? (
                <select
                  className="h-8 min-w-40 rounded-md border border-input bg-input px-3 text-xs"
                  value={nginxScope}
                  onChange={(event) => setNginxScope(event.target.value)}
                >
                  <option value="general">General</option>
                  {nginxSites.map((site) => (
                    <option key={site} value={site}>
                      {site}
                    </option>
                  ))}
                </select>
              ) : null}

              {service === "php" ? (
                <select
                  className="h-8 min-w-44 rounded-md border border-input bg-input px-3 text-xs"
                  value={phpScope}
                  onChange={(event) => setPhpScope(event.target.value)}
                >
                  <option value="current">Current ({phpCurrentLine ?? "not set"})</option>
                  {phpVersions.map((line) => (
                    <option key={line} value={line}>
                      PHP {line}
                    </option>
                  ))}
                </select>
              ) : null}

              {service !== "nginx" ? (
                null
              ) : null}
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void (async () => {
                    await refreshFiles();
                    await refreshContent();
                  })();
                }}
                disabled={loadingContent || loadingFiles}
              >
                {loadingContent ? "..." : "Refresh"}
              </Button>
            </div>
          </div>

          <div className="text-xs text-muted-foreground">
            {service === "nginx"
              ? nginxScope === "general"
                ? "Nginx General"
                : `Nginx Site: ${nginxScope}`
              : selected?.relativePath ?? "No file selected"}
          </div>

          <div className="min-h-0">
            {service === "nginx" ? (
              <div className="grid h-full min-h-0 grid-rows-2 gap-4">
                <LogPanel title="Access Log" panelLines={filteredNginxAccessLines} viewerHeight={220} />
                <LogPanel title="Error Log" panelLines={filteredNginxErrorLines} viewerHeight={220} />
              </div>
            ) : (
              <div className="grid h-full min-h-0">
                <LogPanel
                  title={
                    service === "runtime"
                      ? "Runtime Log"
                      : service === "php"
                        ? "PHP Log"
                        : "MySql Log"
                  }
                  panelLines={filteredLines}
                  viewerHeight={280}
                />
              </div>
            )}
          </div>
        </div>
      </section>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </div>
  );
}
