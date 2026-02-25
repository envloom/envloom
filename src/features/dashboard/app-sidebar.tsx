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
      <div className="overflow-hidden p-0">
        <img src="/logo.svg" alt="Envloom" className="w-full object-contain" />
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
    </aside>
  );
}
