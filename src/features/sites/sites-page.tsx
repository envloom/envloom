import { useEffect, useMemo, useRef, useState } from "react";
import {
  Atom,
  Blend,
  FolderOpen,
  Globe,
  Link2,
  Lock,
  PackagePlus,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Trash2,
  Workflow,
} from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { documentDir } from "@tauri-apps/api/path";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  createSite,
  deleteSite,
  inspectSitePath,
  listSites,
  pickExistingFolder,
  regenerateSiteSsl,
  setSiteSsl,
  setSitePhpVersion,
  type SitePathInspection,
  type SiteRecord,
} from "@/features/sites/sites-api";
import { getPhpCatalog } from "@/features/runtimes/php-api";
import { getNodeCatalog } from "@/features/runtimes/node-api";

type CreationMode = "new" | "link";
type WizardStep = 1 | 2 | 3 | 4;

const DEFAULT_SITES_ROOT = "%USERPROFILE%/Documents/Envloom";

function toErrorMessage(error: unknown, fallback: string) {
  if (typeof error === "string" && error.trim()) return error;
  if (error instanceof Error && error.message.trim()) return error.message;
  if (error && typeof error === "object") {
    const maybeMessage = (error as { message?: unknown }).message;
    if (typeof maybeMessage === "string" && maybeMessage.trim()) return maybeMessage;
    const maybeError = (error as { error?: unknown }).error;
    if (typeof maybeError === "string" && maybeError.trim()) return maybeError;
  }
  return fallback;
}

function toSlug(value: string) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function starterCards() {
  return [
    { value: "none", label: "No starter kit", icon: PackagePlus },
    { value: "react", label: "React", icon: Atom },
    { value: "vue", label: "Vue", icon: Blend },
    { value: "svelte", label: "Svelte", icon: Workflow },
    { value: "livewire", label: "Livewire", icon: PackagePlus },
  ];
}

export function SitesPage() {
  const [sites, setSites] = useState<SiteRecord[]>([]);
  const [sitesLoading, setSitesLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState("");

  const [addOpen, setAddOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState<WizardStep>(1);
  const [creationMode, setCreationMode] = useState<CreationMode | null>(null);
  const [starterKit, setStarterKit] = useState<string | null>(null);
  const [sitesRoot, setSitesRoot] = useState(DEFAULT_SITES_ROOT);

  const [projectName, setProjectName] = useState("");
  const [existingPath, setExistingPath] = useState("");
  const [phpVersion, setPhpVersion] = useState("8.5");
  const [nodeVersion, setNodeVersion] = useState("25");
  const [phpOptions, setPhpOptions] = useState<string[]>(["8.5", "8.4", "8.3", "8.2", "8.1", "7.4"]);
  const [nodeOptions, setNodeOptions] = useState<string[]>(["25", "24", "22", "20", "18"]);
  const [sslEnabled, setSslEnabled] = useState(true);
  const [formError, setFormError] = useState("");
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SiteRecord | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [regeneratingSsl, setRegeneratingSsl] = useState(false);
  const [siteActionError, setSiteActionError] = useState("");
  const [provisionLogs, setProvisionLogs] = useState<string[]>([]);
  const [provisionError, setProvisionError] = useState("");
  const [provisionDone, setProvisionDone] = useState(false);
  const [settingSsl, setSettingSsl] = useState(false);
  const [settingPhpVersion, setSettingPhpVersion] = useState(false);
  const [provisionSiteUrl, setProvisionSiteUrl] = useState("");
  const [pathInspection, setPathInspection] = useState<SitePathInspection | null>(null);
  const [inspectingPath, setInspectingPath] = useState(false);
  const logsPollRef = useRef<number | null>(null);
  const provisionOutputRef = useRef<HTMLDivElement | null>(null);
  const provisionUnlistenRef = useRef<null | (() => void)>(null);

  const filteredSites = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return sites;
    return sites.filter(
      (site) => site.name.toLowerCase().includes(q) || site.domain.toLowerCase().includes(q),
    );
  }, [search, sites]);

  const selectedSite = filteredSites.find((site) => site.id === selectedId) ?? filteredSites[0] ?? null;
  const slug = toSlug(projectName);
  const previewPath = creationMode === "new" ? `${sitesRoot}/${slug || "mynewsite"}` : existingPath.trim();
  const siteUrl = selectedSite
    ? `${selectedSite.sslEnabled ? "https" : "http"}://${selectedSite.domain}`
    : "";

  useEffect(() => {
    let disposed = false;
    if (!isTauri()) {
      setSitesRoot(DEFAULT_SITES_ROOT);
      return () => {
        disposed = true;
      };
    }
    void documentDir()
      .then((documentsPath) => {
        if (disposed) return;
        const normalized = documentsPath.replace(/\\/g, "/").replace(/\/+$/, "");
        setSitesRoot(`${normalized}/Envloom`);
      })
      .catch(() => {
        if (!disposed) setSitesRoot(DEFAULT_SITES_ROOT);
      });
    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    let active = true;
    if (!isTauri()) return () => undefined;
    void (async () => {
      if (provisionUnlistenRef.current) return;
      const unlisten = await listen<string>("site-provision-output", (event) => {
        const line = String(event.payload ?? "");
        setProvisionLogs((prev) => {
          if (prev[prev.length - 1] === line) return prev;
          return [...prev, line].slice(-600);
        });
      });
      if (!active) {
        unlisten();
        return;
      }
      provisionUnlistenRef.current = unlisten;
    })();
    return () => {
      active = false;
      if (provisionUnlistenRef.current) {
        provisionUnlistenRef.current();
        provisionUnlistenRef.current = null;
      }
      if (logsPollRef.current) {
        window.clearInterval(logsPollRef.current);
        logsPollRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    const container = provisionOutputRef.current;
    if (!container) return;
    container.scrollTop = container.scrollHeight;
  }, [provisionLogs]);

  useEffect(() => {
    let cancelled = false;
    void listSites()
      .then((rows) => {
        if (cancelled) return;
        setSites(rows);
        setSelectedId((current) => current || rows[0]?.id || "");
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setSitesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void Promise.all([getPhpCatalog(), getNodeCatalog()])
      .then(([phpCatalog, nodeCatalog]) => {
        if (cancelled) return;
        const phpInstalled = phpCatalog.runtimes
          .filter((runtime) => runtime.installedVersions.length > 0)
          .map((runtime) => runtime.line);
        const nextPhpOptions = phpInstalled.length > 0 ? phpInstalled : ["8.5", "8.4", "8.3", "8.2", "8.1", "7.4"];
        const currentPhp = phpCatalog.currentLine ?? nextPhpOptions[0] ?? "8.5";
        setPhpOptions(nextPhpOptions);
        setPhpVersion(currentPhp);

        const nodeInstalled = nodeCatalog.installedVersions
          .map((value) => value.trim())
          .filter(Boolean)
          .map((value) => value.split(".")[0])
          .filter((value, index, array) => array.indexOf(value) === index);
        const nextNodeOptions = nodeInstalled.length > 0 ? nodeInstalled : ["25", "24", "22", "20", "18"];
        const currentNode = (nodeCatalog.currentVersion?.split(".")[0] ?? nextNodeOptions[0] ?? "25").trim();
        setNodeOptions(nextNodeOptions);
        setNodeVersion(currentNode);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  function resetForm() {
    setWizardStep(1);
    setCreationMode(null);
    setStarterKit(null);
    setProjectName("");
    setExistingPath("");
    setPhpVersion("8.5");
    setNodeVersion("25");
    setSslEnabled(true);
    setFormError("");
    setProvisionLogs([]);
    setProvisionError("");
    setProvisionDone(false);
    setProvisionSiteUrl("");
    setPathInspection(null);
    setInspectingPath(false);
  }

  function closeDialog() {
    setAddOpen(false);
    resetForm();
  }

  function handleNext() {
    setFormError("");
    if (wizardStep === 1) {
      if (!creationMode) {
        setFormError("Select how you want to create the site.");
        return;
      }
      setWizardStep(creationMode === "new" ? 2 : 3);
      return;
    }
    if (wizardStep === 2) {
      if (!starterKit) {
        setFormError("Select a starter kit.");
        return;
      }
      setWizardStep(3);
      return;
    }
    void handleCreateSite();
  }

  function handlePrevious() {
    setFormError("");
    if (wizardStep === 1) {
      closeDialog();
      return;
    }
    if (wizardStep === 2) {
      setWizardStep(1);
      return;
    }
    if (creationMode === "new") {
      setWizardStep(2);
    } else {
      setWizardStep(1);
    }
  }

  async function handleCreateSite() {
    const name = projectName.trim();
    if (!name) {
      setFormError("Project name is required.");
      return;
    }
    if (!slug) {
      setFormError("Project name is not valid.");
      return;
    }
    if (creationMode === "link" && !existingPath.trim()) {
      setFormError("Existing project path is required.");
      return;
    }

    const domain = `${slug}.test`;
    if (sites.some((site) => site.domain.toLowerCase() === domain)) {
      setFormError("A site with the same domain already exists.");
      return;
    }

    try {
      setWizardStep(4);
      setProvisionDone(false);
      setProvisionError("");
      setProvisionLogs(["[Envloom] Starting site provisioning..."]);
      setProvisionSiteUrl("");
      setCreating(true);
      const rows = await createSite({
        name,
        domain,
        linked: creationMode === "link",
        sslEnabled,
        path: creationMode === "new" ? `${sitesRoot}/${slug}` : existingPath.trim(),
        phpVersion,
        nodeVersion,
        starterKit: creationMode === "new" ? starterKit : null,
      });
      setSites(rows);
      const created = rows.find((site) => site.domain.toLowerCase() === domain);
      if (created) {
        setSelectedId(created.id);
        const createdUrl = `${created.sslEnabled ? "https" : "http"}://${created.domain}`;
        setProvisionSiteUrl(createdUrl);
      }
      setProvisionDone(true);
    } catch (error) {
      setProvisionError(toErrorMessage(error, "Failed to create site."));
    } finally {
      setCreating(false);
    }
  }

  function openDeleteDialog(site: SiteRecord) {
    setDeleteTarget(site);
    setDeleteError("");
  }

  async function handleDelete(deleteFiles: boolean) {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      setDeleteError("");
      const rows = await deleteSite(deleteTarget.id, deleteFiles);
      setSites(rows);
      setSelectedId((current) => {
        if (current && rows.some((site) => site.id === current)) return current;
        return rows[0]?.id ?? "";
      });
      setDeleteTarget(null);
    } catch (error) {
      setDeleteError(toErrorMessage(error, "Failed to delete site."));
    } finally {
      setDeleting(false);
    }
  }

  async function handleRegenerateSsl() {
    if (!selectedSite) return;
    try {
      setRegeneratingSsl(true);
      setSiteActionError("");
      const rows = await regenerateSiteSsl(selectedSite.id);
      setSites(rows);
      setSelectedId((current) => current || rows[0]?.id || "");
    } catch (error) {
      setSiteActionError(toErrorMessage(error, "Failed to regenerate SSL."));
    } finally {
      setRegeneratingSsl(false);
    }
  }

  async function handleSetSsl(sslEnabled: boolean) {
    if (!selectedSite) return;
    try {
      setSettingSsl(true);
      setSiteActionError("");
      const rows = await setSiteSsl(selectedSite.id, sslEnabled);
      setSites(rows);
      setSelectedId((current) => current || rows[0]?.id || "");
    } catch (error) {
      setSiteActionError(toErrorMessage(error, "Failed to update SSL mode."));
    } finally {
      setSettingSsl(false);
    }
  }

  async function handleSetSitePhpVersion(nextPhpVersion: string) {
    if (!selectedSite) return;
    try {
      setSettingPhpVersion(true);
      setSiteActionError("");
      const rows = await setSitePhpVersion(selectedSite.id, nextPhpVersion);
      setSites(rows);
      setSelectedId((current) => current || rows[0]?.id || "");
    } catch (error) {
      setSiteActionError(toErrorMessage(error, "Failed to update site PHP version."));
    } finally {
      setSettingPhpVersion(false);
    }
  }

  async function handleOpenProvisionedSite() {
    if (!provisionSiteUrl) return;
    if (!isTauri()) {
      window.open(provisionSiteUrl, "_blank", "noopener,noreferrer");
      return;
    }
    await openUrl(provisionSiteUrl);
  }

  async function inspectPathValue(path: string) {
    const value = path.trim();
    if (!value) {
      setPathInspection(null);
      return;
    }
    try {
      setInspectingPath(true);
      const inspection = await inspectSitePath(value);
      setPathInspection(inspection);
      if (inspection.suggestedName && !projectName.trim()) {
        setProjectName(inspection.suggestedName);
      }
    } finally {
      setInspectingPath(false);
    }
  }

  async function handleBrowseExistingPath() {
    try {
      const selected = await pickExistingFolder();
      if (!selected) return;
      setExistingPath(selected);
      await inspectPathValue(selected);
    } catch (error) {
      setFormError(toErrorMessage(error, "Failed to open folder picker."));
    }
  }

  return (
    <div className="grid h-full gap-4">
      <section className="rounded-2xl border bg-card/60 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="rounded-lg bg-primary/15 p-2 text-primary">
              <Globe className="size-5" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">Sites</h1>
              <p className="text-sm text-muted-foreground">Create, link and serve local apps.</p>
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <div className="rounded-md border px-3 py-1 text-sm text-muted-foreground">
              {sites.length} total
            </div>
            <Button size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="mr-1 size-4" />
              New Site
            </Button>
          </div>
        </div>
      </section>

      <section className="grid min-h-0 flex-1 gap-4 md:grid-cols-[320px_1fr]">
        <aside className="flex min-h-0 flex-col rounded-2xl border bg-card/50">
          <div className="border-b p-3">
            <div className="relative">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Find site..."
                className="pl-9"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {sitesLoading
              ? Array.from({ length: 6 }).map((_, index) => (
                  <div key={`site-skeleton-${index}`} className="mb-2 rounded-xl border p-2">
                    <Skeleton className="h-4 w-40" />
                    <Skeleton className="mt-2 h-3 w-24" />
                  </div>
                ))
              : filteredSites.map((site) => {
              const active = selectedSite?.id === site.id;
              return (
                <div
                  key={site.id}
                  className={`mb-2 rounded-xl border p-2 transition-colors ${
                    active ? "border-primary bg-primary/10" : "hover:bg-accent/60"
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <button className="min-w-0 flex-1 text-left" onClick={() => setSelectedId(site.id)}>
                      <p className="truncate text-sm font-medium">{site.domain}</p>
                      <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                        {site.linked ? <Link2 className="size-3.5" /> : <Shield className="size-3.5" />}
                        <span>{site.linked ? "Linked" : "Managed"}</span>
                        {site.sslEnabled ? <Lock className="size-3.5" /> : null}
                      </div>
                    </button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-7"
                      onClick={() => openDeleteDialog(site)}
                      title={`Delete ${site.domain}`}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        <div className="min-h-0 min-w-0 overflow-y-auto rounded-2xl border bg-card/50 p-4">
          {sitesLoading ? (
            <div className="grid gap-4">
              <Skeleton className="h-7 w-56" />
              <Skeleton className="h-4 w-80" />
              <Separator />
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-xl border bg-background/60 p-3">
                  <Skeleton className="h-3 w-20" />
                  <Skeleton className="mt-3 h-4 w-36" />
                  <Skeleton className="mt-2 h-4 w-28" />
                </div>
                <div className="rounded-xl border bg-background/60 p-3">
                  <Skeleton className="h-3 w-20" />
                  <Skeleton className="mt-3 h-4 w-48" />
                  <Skeleton className="mt-2 h-4 w-24" />
                </div>
              </div>
              <div className="rounded-xl border bg-background/60 p-3">
                <Skeleton className="h-3 w-24" />
                <Skeleton className="mt-3 h-4 w-full" />
              </div>
            </div>
          ) : selectedSite ? (
            <div className="grid gap-4">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-2xl font-semibold">{selectedSite.name}</h2>
                <span className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground">
                  {selectedSite.linked ? "Linked project" : "Managed project"}
                </span>
                <span className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground">
                  {selectedSite.sslEnabled ? "SSL On" : "SSL Off"}
                </span>
                {selectedSite.sslEnabled ? (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void handleRegenerateSsl()}
                    disabled={regeneratingSsl}
                    className="ml-auto"
                  >
                    <RefreshCw className={`mr-1 size-4 ${regeneratingSsl ? "animate-spin" : ""}`} />
                    {regeneratingSsl ? "Regenerating..." : "Regenerate SSL"}
                  </Button>
                ) : null}
              </div>
              {siteActionError ? <p className="text-sm text-destructive">{siteActionError}</p> : null}
              <Separator />

              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-xl border bg-background/60 p-3">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">Runtime</p>
                  <div className="mt-2 grid gap-2 text-sm">
                    <div className="flex justify-between gap-2">
                      <span className="text-muted-foreground">PHP</span>
                      <select
                        className="h-8 min-w-28 rounded-md border border-input bg-input px-2 text-sm"
                        value={selectedSite.phpVersion}
                        onChange={(event) => void handleSetSitePhpVersion(event.target.value)}
                        disabled={settingPhpVersion}
                      >
                        {phpOptions.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-muted-foreground">Node</span>
                      <span>{selectedSite.nodeVersion}</span>
                    </div>
                  </div>
                </div>
                <div className="rounded-xl border bg-background/60 p-3">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">Access</p>
                  <div className="mt-2 grid gap-2 text-sm">
                    <div className="flex justify-between gap-2">
                      <span className="text-muted-foreground">URL</span>
                      <a
                        href={siteUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="truncate text-primary underline-offset-2 hover:underline"
                      >
                        {siteUrl}
                      </a>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-muted-foreground">SSL</span>
                      <span>{selectedSite.sslEnabled ? "Enabled" : "Disabled"}</span>
                    </div>
                    <div className="pt-1">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void handleSetSsl(!selectedSite.sslEnabled)}
                        disabled={settingSsl}
                      >
                        {settingSsl
                          ? "Updating..."
                          : selectedSite.sslEnabled
                            ? "Switch to non-SSL"
                            : "Switch to SSL"}
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border bg-background/60 p-3 text-sm">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Project Path</p>
                <p className="mt-2 break-all">{selectedSite.path}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No sites available.</p>
          )}
        </div>
      </section>

      <Dialog
        open={addOpen}
        onOpenChange={(open) => {
          setAddOpen(open);
          if (!open) resetForm();
        }}
      >
        <DialogContent className="max-w-5xl! w-[min(96vw,1120px)]! p-0!">
          <DialogHeader className="border-b px-6 py-5">
            <DialogTitle>Create New Site</DialogTitle>
            <DialogDescription>
              {wizardStep === 1
                ? "Choose how the site will be created."
                : wizardStep === 2
                  ? "Select a starter kit."
                  : wizardStep === 3
                    ? "Configure your project information."
                    : "Provisioning site..."}
            </DialogDescription>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {[1, 2, 3, 4].map((step) => {
                const active = wizardStep === step;
                const done = wizardStep > step;
                return (
                  <span
                    key={`wizard-step-${step}`}
                    className={`rounded-full border px-2.5 py-1 text-xs ${
                      active
                        ? "border-primary bg-primary/15 text-foreground"
                        : done
                          ? "border-primary/40 bg-primary/10 text-muted-foreground"
                          : "text-muted-foreground"
                    }`}
                  >
                    Step {step}
                  </span>
                );
              })}
            </div>
          </DialogHeader>

          {wizardStep === 1 ? (
            <div className="grid gap-4 px-6 py-5 sm:grid-cols-2">
              <button
                className={`grid min-h-52 place-items-center gap-3 rounded-xl border p-8 text-center transition-colors ${
                  creationMode === "new" ? "border-primary bg-accent" : "hover:bg-accent/70"
                }`}
                onClick={() => setCreationMode("new")}
              >
                <PackagePlus className="size-9 text-muted-foreground" />
                <span className="text-base font-medium">New Laravel project</span>
              </button>
              <button
                className={`grid min-h-52 place-items-center gap-3 rounded-xl border p-8 text-center transition-colors ${
                  creationMode === "link" ? "border-primary bg-accent" : "hover:bg-accent/70"
                }`}
                onClick={() => setCreationMode("link")}
              >
                <FolderOpen className="size-9 text-muted-foreground" />
                <span className="text-base font-medium">Link existing project</span>
              </button>
            </div>
          ) : null}

          {wizardStep === 2 ? (
            <div className="grid gap-3 px-6 py-5 sm:grid-cols-3">
              {starterCards().map((item) => (
                <button
                  key={item.value}
                  className={`grid min-h-36 place-items-center gap-2 rounded-xl border p-6 text-center transition-colors ${
                    starterKit === item.value ? "border-primary bg-accent" : "hover:bg-accent/70"
                  }`}
                  onClick={() => setStarterKit(item.value)}
                >
                  <item.icon className="size-7 text-muted-foreground" />
                  <span className="text-sm font-medium">{item.label}</span>
                </button>
              ))}
            </div>
          ) : null}

          {wizardStep === 3 ? (
            <div className="grid gap-3 px-6 py-5">
              <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                <p className="text-right text-sm">Project Name:</p>
                <Input value={projectName} onChange={(event) => setProjectName(event.target.value)} />
              </div>
              <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                <p className="text-right text-sm">PHP Version:</p>
                <select
                  className="h-9 rounded-md border border-input bg-input px-3 text-sm"
                  value={phpVersion}
                  onChange={(event) => setPhpVersion(event.target.value)}
                >
                  {phpOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                <p className="text-right text-sm">SSL:</p>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={sslEnabled}
                    onChange={(event) => setSslEnabled(event.target.checked)}
                    className="size-4 accent-primary"
                  />
                  Enable local SSL
                </label>
              </div>
              <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                <p className="text-right text-sm">Node Version:</p>
                <select
                  className="h-9 rounded-md border border-input bg-input px-3 text-sm"
                  value={nodeVersion}
                  onChange={(event) => setNodeVersion(event.target.value)}
                >
                  {nodeOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
              {creationMode === "link" ? (
                <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                  <p className="text-right text-sm">Existing Path:</p>
                  <Input
                    value={existingPath}
                    onChange={(event) => {
                      setExistingPath(event.target.value);
                      void inspectPathValue(event.target.value);
                    }}
                    placeholder="D:/work/my-existing-project"
                  />
                </div>
              ) : null}
              {creationMode === "link" ? (
                <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                  <div />
                  <div className="flex items-center gap-2">
                    <Button type="button" variant="outline" size="sm" onClick={() => void handleBrowseExistingPath()}>
                      Browse...
                    </Button>
                    {inspectingPath ? <span className="text-xs text-muted-foreground">Inspecting...</span> : null}
                  </div>
                </div>
              ) : null}
              {creationMode === "link" && pathInspection ? (
                <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                  <p className="text-right text-sm">Detected:</p>
                  <div className="text-sm text-muted-foreground">
                    {pathInspection.exists && pathInspection.isDirectory
                      ? pathInspection.isPhpProject
                        ? `Framework: ${pathInspection.framework}`
                        : "Not detected as PHP project"
                      : "Path does not exist or is not a folder"}
                  </div>
                </div>
              ) : null}
              {creationMode === "new" ? (
                <div className="grid grid-cols-[190px_1fr] items-center gap-3">
                  <p className="text-right text-sm">Will be created at:</p>
                  <Input value={previewPath} readOnly />
                </div>
              ) : null}
            </div>
          ) : null}

          {wizardStep === 4 ? (
            <div className="grid gap-3 px-6 py-5">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <RefreshCw className={`size-4 ${creating ? "animate-spin" : ""}`} />
                {creating ? "Running setup commands..." : provisionDone ? "Provisioning completed." : "Provisioning stopped."}
              </div>
              <div
                ref={provisionOutputRef}
                className="h-64 overflow-auto rounded-md border bg-background p-3 font-mono text-xs leading-5"
              >
                {provisionLogs.length === 0 ? (
                  <span className="text-muted-foreground">Waiting for output...</span>
                ) : (
                  provisionLogs.map((line, index) => (
                    <div key={`${index}-${line.slice(0, 12)}`}>{line}</div>
                  ))
                )}
              </div>
            </div>
          ) : null}

          {formError ? <p className="px-6 text-sm text-destructive">{formError}</p> : null}
          {provisionError ? <p className="px-6 text-sm text-destructive">{provisionError}</p> : null}

          <DialogFooter className="border-t px-6 py-4">
            {wizardStep === 4 ? (
              <>
                <Button variant="outline" onClick={closeDialog} disabled={creating}>
                  {provisionDone ? "Close" : "Cancel"}
                </Button>
                {provisionDone && provisionSiteUrl ? (
                  <Button onClick={() => void handleOpenProvisionedSite()}>
                    Open in browser
                  </Button>
                ) : null}
                {!provisionDone ? (
                  <Button disabled>
                    {creating ? "Creating..." : "Processing..."}
                  </Button>
                ) : null}
              </>
            ) : (
              <>
                <Button variant="outline" onClick={handlePrevious}>
                  {wizardStep === 1 ? "Cancel" : "Previous"}
                </Button>
                <Button onClick={handleNext} disabled={creating}>
                  {creating ? "Creating..." : wizardStep === 3 ? "Create Site" : "Next"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!deleteTarget} onOpenChange={(open) => (!open ? setDeleteTarget(null) : undefined)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Delete Site</DialogTitle>
            <DialogDescription>
              {deleteTarget
                ? `What do you want to do with ${deleteTarget.domain}?`
                : "Choose how to delete the site."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-2 text-sm">
            <p className="text-muted-foreground">Path: {deleteTarget?.path ?? "-"}</p>
            {deleteError ? <p className="text-destructive">{deleteError}</p> : null}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={deleting}>
              Cancel
            </Button>
            <Button variant="outline" onClick={() => void handleDelete(false)} disabled={deleting}>
              Disconnect
            </Button>
            <Button variant="destructive" onClick={() => void handleDelete(true)} disabled={deleting}>
              {deleting ? "Deleting..." : "Delete files and remove"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
