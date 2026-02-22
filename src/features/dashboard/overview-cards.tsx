import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { getServiceStatuses, type ServiceStatusItem } from "./services-api";
import { listSites, type SiteRecord } from "@/features/sites/sites-api";

const fallbackServices: ServiceStatusItem[] = [
  { key: "php", label: "PHP", status: "stopped", healthy: false, version: "-", port: "-" },
  { key: "node", label: "Node", status: "stopped", healthy: false, version: "-", port: "-" },
  { key: "mysql", label: "MySQL", status: "stopped", healthy: false, version: "-", port: "-" },
  { key: "nginx", label: "Nginx", status: "stopped", healthy: false, version: "-", port: "-" },
];

type OverviewCardsProps = {
  isStarting?: boolean;
  onNavigateToSites?: () => void;
};

export function OverviewCards({ isStarting = false, onNavigateToSites }: OverviewCardsProps) {
  const [services, setServices] = useState<ServiceStatusItem[]>(fallbackServices);
  const [sites, setSites] = useState<SiteRecord[]>([]);
  const [sitesLoading, setSitesLoading] = useState(true);

  useEffect(() => {
    let disposed = false;
    async function refresh() {
      try {
        const response = await getServiceStatuses();
        if (!disposed) setServices(response);
      } catch {
        if (!disposed) setServices(fallbackServices);
      }
    }
    void refresh();
    const timer = window.setInterval(() => {
      void refresh();
    }, 15000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    async function refreshSites() {
      try {
        const rows = await listSites();
        if (!disposed) setSites(rows.slice(0, 10));
      } catch {
        if (!disposed) setSites([]);
      } finally {
        if (!disposed) setSitesLoading(false);
      }
    }
    void refreshSites();
    const timer = window.setInterval(() => {
      void refreshSites();
    }, 15000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, []);

  const displayedServices = isStarting
    ? services.map((service) =>
        service.healthy ? service : { ...service, status: "starting", healthy: false },
      )
    : services;

  return (
    <section className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader>
          <CardDescription>Service Status</CardDescription>
          <CardTitle>Top services</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {displayedServices.map((service) => (
            <div key={service.key} className="flex items-center justify-between rounded-md border px-3 py-2">
              <div className="flex items-center gap-2">
                <span
                  className={`inline-flex size-2 rounded-full ${
                    service.status.toLowerCase().includes("starting")
                      ? "bg-amber-500 animate-pulse"
                      : service.healthy
                        ? "bg-emerald-500"
                        : "bg-red-500"
                  }`}
                />
                <p className="text-sm font-medium">{service.label}</p>
              </div>
              <p className="text-xs text-muted-foreground">
                {service.version} - {service.status}
              </p>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-start justify-between gap-3 space-y-0">
          <div>
            <CardDescription>Sites</CardDescription>
            <CardTitle>Recent sites</CardTitle>
          </div>
          <Button variant="outline" size="sm" onClick={onNavigateToSites}>
            View more
          </Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {sitesLoading ? (
            <p className="text-sm text-muted-foreground">Loading sites...</p>
          ) : sites.length === 0 ? (
            <p className="text-sm text-muted-foreground">No sites registered.</p>
          ) : (
            sites.map((site) => {
              const url = `${site.sslEnabled ? "https" : "http"}://${site.domain}`;
              return (
                <div key={site.id} className="rounded-md border px-3 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-sm font-medium">{site.name}</p>
                    <span className="text-xs text-muted-foreground">{site.sslEnabled ? "SSL" : "No SSL"}</span>
                  </div>
                  <div className="mt-1 flex items-center justify-between gap-2">
                    <a href={url} target="_blank" rel="noreferrer" className="truncate text-xs text-primary hover:underline">
                      {url}
                    </a>
                    <span className="text-xs text-muted-foreground">PHP {site.phpVersion}</span>
                  </div>
                </div>
              );
            })
          )}
        </CardContent>
      </Card>
    </section>
  );
}
