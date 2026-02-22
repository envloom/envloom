import {useEffect, useState} from "react";
import { isTauri } from "@tauri-apps/api/core";
import {listen} from "@tauri-apps/api/event";
import {AppSidebar} from "@/features/dashboard/app-sidebar";
import {TopHeader} from "@/features/dashboard/top-header";
import {RuntimesPage} from "@/features/runtimes/runtimes-page";
import {NodePage} from "@/features/runtimes/node-page";
import {MariaDbPage} from "@/features/runtimes/mariadb-page";
import {OverviewCards} from "@/features/dashboard/overview-cards.tsx";
import {SitesPage} from "@/features/sites/sites-page.tsx";
import {LogsPage} from "@/features/logs/logs-page";
import {SettingsPage} from "@/features/settings/settings-page";

type BootstrapProgressEvent = {
  phase: string;
  status: string;
  percent?: number | null;
  message: string;
};

function getCurrentRoute() {
  const hash = window.location.hash.replace(/^#/, "");
  const route = !hash ? "/dashboard" : hash.startsWith("/") ? hash : `/${hash}`;
  const normalized = route.replace(/\/+$/, "") || "/dashboard";
  if (normalized === "/" || normalized === "/inicio" || normalized === "/dashboard") {
    return "/dashboard";
  }
  if (normalized === "/runtimes") {
    return "/runtimes/php";
  }
  if (normalized === "/runtimes/nginx") {
    return "/runtimes/php";
  }
  if (normalized === "/runtimes/mysql") {
    return "/runtimes/mariadb";
  }
  if (normalized === "/projects") {
    return "/sites";
  }
  return normalized;
}

function App() {
  const [route, setRoute] = useState(getCurrentRoute);
  const [bootstrapProgress, setBootstrapProgress] = useState<BootstrapProgressEvent | null>(null);
  const [phpSplashVisible, setPhpSplashVisible] = useState(false);
  const [composerStatus, setComposerStatus] = useState<BootstrapProgressEvent | null>(null);
  const [servicesStarting, setServicesStarting] = useState(false);

  useEffect(() => {
    const handleHashChange = () => setRoute(getCurrentRoute());
    window.addEventListener("hashchange", handleHashChange);
    let unlisten: (() => void) | null = null;
    if (!isTauri()) {
      return () => {
        window.removeEventListener("hashchange", handleHashChange);
      };
    }
    void listen<BootstrapProgressEvent>("bootstrap-progress", (event) => {
      const payload = event.payload;
      if (payload.phase === "php") {
        setBootstrapProgress(payload);
        if (payload.status === "completed" || payload.status === "skipped" || payload.status === "error") {
          setPhpSplashVisible(false);
          window.setTimeout(() => setBootstrapProgress(null), 800);
        } else {
          setPhpSplashVisible(true);
        }
      }
      if (
        payload.phase === "composer" ||
        payload.phase === "nvm" ||
        payload.phase === "nginx" ||
        payload.phase === "mariadb" ||
        payload.phase === "services"
      ) {
        if (phpSplashVisible && !bootstrapProgress) {
          setPhpSplashVisible(false);
        }
        if (payload.phase === "services") {
          setServicesStarting(payload.status === "started" || payload.status === "progress");
        }
        setComposerStatus(payload);
        if (payload.status === "completed" || payload.status === "error") {
          window.setTimeout(() => setComposerStatus(null), 2500);
        }
      }
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      window.removeEventListener("hashchange", handleHashChange);
      if (unlisten) unlisten();
    };
  }, []);

  function navigate(nextRoute: string) {
    window.location.hash = nextRoute === "/dashboard" ? "" : nextRoute;
    setRoute(getCurrentRoute());
  }

  const isPhpRoute = route === "/runtimes/php";
  const isNodeRoute = route === "/runtimes/node";
  const isMariaDbRoute = route === "/runtimes/mariadb";
  const isSitesRoute = route === "/sites";
  const isLogsRoute = route === "/logs";
  const isSettingsRoute = route === "/settings";

  return (
    <div className="h-screen overflow-hidden bg-[radial-gradient(ellipse_at_top,hsl(var(--secondary)),hsl(var(--background))_45%)] p-4 md:p-6">
      <div className={`fixed top-4 bottom-4 left-4 w-65 md:top-6 md:bottom-6 md:left-6 ${phpSplashVisible ? "invisible" : ""}`}>
        <AppSidebar currentRoute={route} onNavigate={navigate} />
      </div>

      <div className={`h-full pl-70 md:pl-75 ${phpSplashVisible ? "invisible" : ""}`}>
        <main className="h-full overflow-y-auto pr-1">
          <div className="grid gap-4">
            {isPhpRoute ? (
              <RuntimesPage />
            ) : isNodeRoute ? (
              <NodePage />
            ) : isMariaDbRoute ? (
              <MariaDbPage />
            ) : isSitesRoute ? (
              <SitesPage />
            ) : isLogsRoute ? (
              <LogsPage />
            ) : isSettingsRoute ? (
              <SettingsPage />
            ) : (
              <>
                <TopHeader onServicesStartingChange={setServicesStarting} />
                <OverviewCards isStarting={servicesStarting} onNavigateToSites={() => navigate("/sites")} />
              </>
            )}
          </div>
        </main>
      </div>
      {phpSplashVisible && bootstrapProgress?.phase === "php" ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-background">
          <div className="w-[min(560px,92vw)] rounded-xl border bg-card p-6 shadow-md">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Preparing environment</p>
            <h2 className="mt-1 text-xl font-semibold">Downloading PHP runtime</h2>
            <p className="mt-2 text-sm text-muted-foreground">{bootstrapProgress.message}</p>
            <div className="mt-4 h-2 w-full rounded bg-muted">
              <div
                className="h-2 rounded bg-primary transition-all"
                style={{
                  width: `${Math.max(0, Math.min(100, bootstrapProgress.percent ?? 0))}%`,
                }}
              />
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              {typeof bootstrapProgress.percent === "number"
                ? `${Math.round(bootstrapProgress.percent)}%`
                : bootstrapProgress.status}
            </p>
          </div>
        </div>
      ) : null}
      {composerStatus ? (
        <div className="fixed right-4 bottom-4 z-40 w-80 rounded-lg border bg-card p-3 shadow-md">
          <p className="text-xs uppercase tracking-wide text-muted-foreground">
            {composerStatus.phase}
          </p>
          <p className="text-sm font-medium">{composerStatus.message}</p>
          <p className="mt-1 text-xs text-muted-foreground">{composerStatus.status}</p>
        </div>
      ) : null}
    </div>
  );
}

export default App;
