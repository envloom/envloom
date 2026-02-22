import { useState } from "react";
import { Button } from "@/components/ui/button";
import { startAllServices, stopAllServices } from "./services-api";

type TopHeaderProps = {
  onServicesStartingChange?: (starting: boolean) => void;
};

export function TopHeader({ onServicesStartingChange }: TopHeaderProps) {
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState("");

  async function handleStartAll() {
    setStarting(true);
    onServicesStartingChange?.(true);
    setError("");
    try {
      await startAllServices();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err ?? "Failed to start services.");
      setError(message);
    } finally {
      setStarting(false);
      onServicesStartingChange?.(false);
    }
  }

  async function handleStopAll() {
    setStopping(true);
    onServicesStartingChange?.(true);
    setError("");
    try {
      await stopAllServices();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err ?? "Failed to stop services.");
      setError(message);
    } finally {
      setStopping(false);
      onServicesStartingChange?.(false);
    }
  }

  return (
    <header className="flex flex-col gap-4 rounded-2xl border bg-card/90 p-4 shadow-sm sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="text-xs uppercase tracking-wider text-muted-foreground">Environment</p>
        <h1 className="text-2xl font-semibold tracking-tight">Developer Control Center</h1>
        <p className="text-sm text-muted-foreground">
          Manage runtimes, services and per-project configuration.
        </p>
        {error ? <p className="mt-2 text-xs text-destructive">{error}</p> : null}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => void handleStartAll()} disabled={starting || stopping}>
          {starting ? "Starting..." : "Start all"}
        </Button>
        <Button variant="outline" onClick={() => void handleStopAll()} disabled={starting || stopping}>
          {stopping ? "Stopping..." : "Stop all"}
        </Button>
        <Button variant="outline">Restart stack</Button>
      </div>
    </header>
  );
}
