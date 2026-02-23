import type { ReactNode } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function RuntimePageShell({
  title,
  subtitle,
  stats,
  children,
}: {
  title: string;
  subtitle: string;
  stats?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-5">
      <div className="relative overflow-hidden rounded-2xl border bg-gradient-to-br from-background via-background to-muted/30 p-6 shadow-sm">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,hsl(var(--primary)/0.12),transparent_45%),radial-gradient(circle_at_85%_15%,hsl(var(--accent)/0.08),transparent_40%)]" />
        <div className="relative grid gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Runtime Manager</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight">{title}</h1>
            <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
          </div>
          {stats ? <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{stats}</div> : null}
        </div>
      </div>
      {children}
    </div>
  );
}

export function RuntimeStat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <Card className="gap-3 py-4">
      <CardContent className="px-4">
        <p className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</p>
        <div className="mt-1 text-lg font-semibold leading-none">{value}</div>
        {hint ? <p className="mt-2 text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

export function RuntimePanel({
  title,
  description,
  action,
  children,
  className,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("gap-4 py-0", className)}>
      <CardHeader className="border-b py-4">
        <div className="grid gap-1">
          <CardTitle>{title}</CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </div>
        {action ? <div data-slot="card-action">{action}</div> : null}
      </CardHeader>
      <CardContent className="pb-5">{children}</CardContent>
    </Card>
  );
}

