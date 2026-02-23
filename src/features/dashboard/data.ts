import {
  Activity,
  FolderKanban,
  Server,
  Settings,
  TerminalSquare,
} from "lucide-react";
import { Php } from "@/components/icons/php";
import { Nodejs } from "@/components/icons/node";

export const navItems = [
  { label: "Dashboard", icon: Activity, route: "/dashboard" },
  { label: "Sites", icon: FolderKanban, route: "/sites" },
  { label: "PHP", icon: Php, route: "/runtimes/php" },
  { label: "Node", icon: Nodejs, route: "/runtimes/node" },
  { label: "MariaDB", icon: Server, route: "/runtimes/mariadb" },
  { label: "Logs", icon: TerminalSquare, route: "/logs" },
  { label: "Settings", icon: Settings, route: "/settings" },
];

export const services = [
  { name: "Nginx", status: "running", port: "80 / 443", version: "1.27.4" },
  { name: "PHP-FPM", status: "running", port: "9000", version: "8.3.6" },
  { name: "MariaDB", status: "running", port: "3306", version: "11.4.8" },
  { name: "Node Tooling", status: "idle", port: "-", version: "20.19.2" },
];

export const projects = [
  {
    name: "acme-api",
    path: "D:/work/acme-api",
    domain: "acme-api.test",
    php: "8.2",
    node: "20",
    mariadb: "11.4",
  },
  {
    name: "storefront",
    path: "D:/work/storefront",
    domain: "storefront.test",
    php: "8.3",
    node: "22",
    mariadb: "11.4",
  },
  {
    name: "legacy-cms",
    path: "D:/work/legacy-cms",
    domain: "legacy-cms.test",
    php: "7.4",
    node: "18",
    mariadb: "10.11",
  },
];
