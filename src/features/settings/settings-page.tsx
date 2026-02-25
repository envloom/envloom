import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { getAppSettings, setAppSettings, type AppSettingsResponse } from "./settings-api";

function toErrorMessage(error: unknown, fallback: string) {
  if (typeof error === "string" && error.trim()) return error;
  if (error instanceof Error && error.message.trim()) return error.message;
  return fallback;
}

export function SettingsPage() {
  const [settings, setSettings] = useState<AppSettingsResponse | null>(null);
  const [autoStart, setAutoStart] = useState(true);
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [startWithWindows, setStartWithWindows] = useState(false);
  const [startMinimized, setStartMinimized] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const response = await getAppSettings();
      setSettings(response);
      setAutoStart(response.autoStartServices);
      setAutoUpdate(response.autoUpdate);
      setStartWithWindows(response.startWithWindows);
      setStartMinimized(response.startMinimized);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to load settings."));
    } finally {
      setLoading(false);
    }
  }

  async function save() {
    setSaving(true);
    setError("");
    try {
      const response = await setAppSettings(autoStart, autoUpdate, startWithWindows, startMinimized);
      setSettings(response);
      setAutoStart(response.autoStartServices);
      setAutoUpdate(response.autoUpdate);
      setStartWithWindows(response.startWithWindows);
      setStartMinimized(response.startMinimized);
    } catch (err) {
      setError(toErrorMessage(err, "Failed to save settings."));
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  return (
    <div className="grid gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">Global Envloom behavior stored in <code>~/.envloom/config.json</code>.</p>
      </div>
      <Separator />

      <section className="grid gap-4 rounded-xl border bg-card/50 p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">Auto-start services on app launch</p>
            <p className="text-sm text-muted-foreground">
              Starts MariaDB and Nginx automatically during bootstrap.
            </p>
          </div>
          <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={autoStart}
              onChange={(event) => setAutoStart(event.target.checked)}
              disabled={loading || saving}
            />
            {autoStart ? "On" : "Off"}
          </label>
        </div>

        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">Auto-check runtime updates</p>
            <p className="text-sm text-muted-foreground">
              Enables the hourly background check for PHP, Node and MariaDB updates.
            </p>
          </div>
          <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={autoUpdate}
              onChange={(event) => setAutoUpdate(event.target.checked)}
              disabled={loading || saving}
            />
            {autoUpdate ? "On" : "Off"}
          </label>
        </div>

        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">Start with Windows</p>
            <p className="text-sm text-muted-foreground">
              Registers Envloom in your Windows startup apps (current user).
            </p>
          </div>
          <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={startWithWindows}
              onChange={(event) => setStartWithWindows(event.target.checked)}
              disabled={loading || saving}
            />
            {startWithWindows ? "On" : "Off"}
          </label>
        </div>

        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">Start minimized</p>
            <p className="text-sm text-muted-foreground">
              Starts hidden to tray when launched from the Windows startup entry.
            </p>
          </div>
          <label className="inline-flex cursor-pointer items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={startMinimized}
              onChange={(event) => setStartMinimized(event.target.checked)}
              disabled={loading || saving}
            />
            {startMinimized ? "On" : "Off"}
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-2">
          <Button variant="outline" onClick={() => void refresh()} disabled={loading || saving}>
            {loading ? "Loading..." : "Refresh"}
          </Button>
          <Button onClick={() => void save()} disabled={loading || saving}>
            {saving ? "Saving..." : "Save settings"}
          </Button>
          {settings ? (
            <span className="text-xs text-muted-foreground">
              File: {settings.configPath}
            </span>
          ) : null}
        </div>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
      </section>
    </div>
  );
}
