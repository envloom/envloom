import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { navItems } from "./data";

type AppSidebarProps = {
  currentRoute: string;
  onNavigate: (route: string) => void;
};

export function AppSidebar({ currentRoute, onNavigate }: AppSidebarProps) {
  return (
    <aside className="flex h-full flex-col rounded-2xl border bg-sidebar/80 p-4 text-sidebar-foreground shadow-sm backdrop-blur">
      <div className="flex items-center gap-3">
        <div className="grid size-10 place-items-center rounded-xl bg-sidebar-primary text-sidebar-primary-foreground">
          PN
        </div>
        <div>
          <p className="font-semibold leading-none">Envloom</p>
          <p className="text-xs text-muted-foreground">Local Stack Manager</p>
        </div>
      </div>
      <Separator className="my-4" />
      <nav className="grid gap-1">
        {navItems.map((item) => (
          <Button
            key={item.label}
            variant={currentRoute === item.route ? "secondary" : "ghost"}
            className="justify-start gap-2"
            onClick={() => onNavigate(item.route)}
          >
            <item.icon className="size-4" />
            {item.label}
          </Button>
        ))}
      </nav>
      <div className="mt-auto rounded-xl border bg-card p-3">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">Systray status</p>
        <div className="mt-2 flex items-center gap-2">
          <span className="inline-flex size-2 rounded-full bg-emerald-500"></span>
          <p className="text-sm font-medium">All services healthy</p>
        </div>
      </div>
    </aside>
  );
}
