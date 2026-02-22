import { useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  addRuntimeVersion,
  listRuntimes,
  removeRuntimeVersion,
  setActiveRuntime,
  type RuntimeItem,
} from "@/features/runtimes/api";
import { projects } from "./data";

export function RuntimesAndProjects() {
  const [runtimes, setRuntimes] = useState<RuntimeItem[]>([]);
  const [runtimeLoading, setRuntimeLoading] = useState(true);
  const [runtimeError, setRuntimeError] = useState<string>("");
  const [runtimeToAdd, setRuntimeToAdd] = useState("php");
  const [versionToAdd, setVersionToAdd] = useState("");
  const [projectSearch, setProjectSearch] = useState("");

  const runtimeKeys = useMemo(() => runtimes.map((r) => r.runtime), [runtimes]);

  useEffect(() => {
    const initialRuntime = runtimeKeys[0];
    if (initialRuntime && !runtimeKeys.includes(runtimeToAdd)) {
      setRuntimeToAdd(initialRuntime);
    }
  }, [runtimeKeys, runtimeToAdd]);

  useEffect(() => {
    void refreshRuntimes();
  }, []);

  async function refreshRuntimes() {
    setRuntimeLoading(true);
    setRuntimeError("");
    try {
      const data = await listRuntimes();
      setRuntimes(data);
      if (data.length > 0 && !data.some((item) => item.runtime === runtimeToAdd)) {
        setRuntimeToAdd(data[0].runtime);
      }
    } catch (error) {
      setRuntimeError(error instanceof Error ? error.message : "Failed to load runtimes");
    } finally {
      setRuntimeLoading(false);
    }
  }

  async function handleSetActive(runtime: string, version: string) {
    setRuntimeError("");
    try {
      const data = await setActiveRuntime(runtime, version);
      setRuntimes(data);
    } catch (error) {
      setRuntimeError(error instanceof Error ? error.message : "Failed to set active runtime");
    }
  }

  async function handleAddVersion() {
    if (!versionToAdd.trim()) return;
    setRuntimeError("");
    try {
      const data = await addRuntimeVersion(runtimeToAdd, versionToAdd.trim());
      setRuntimes(data);
      setVersionToAdd("");
    } catch (error) {
      setRuntimeError(error instanceof Error ? error.message : "Failed to add version");
    }
  }

  async function handleRemoveVersion(runtime: string, version: string) {
    setRuntimeError("");
    try {
      const data = await removeRuntimeVersion(runtime, version);
      setRuntimes(data);
    } catch (error) {
      setRuntimeError(error instanceof Error ? error.message : "Failed to remove version");
    }
  }

  const filteredProjects = projects.filter((project) =>
    `${project.name} ${project.path} ${project.domain}`.toLowerCase().includes(projectSearch.toLowerCase()),
  );

  return (
    <Tabs defaultValue="runtimes" className="gap-4">
      <TabsList>
        <TabsTrigger value="runtimes">Runtimes</TabsTrigger>
        <TabsTrigger value="projects">Projects</TabsTrigger>
      </TabsList>
      <TabsContent value="runtimes">
        <Card>
          <CardHeader>
            <CardTitle>Runtime Versions</CardTitle>
            <CardDescription>Active and installed versions from Tauri backend</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-2 sm:grid-cols-[1fr_180px_auto]">
              <Input
                placeholder="Version to add, e.g. 8.4.1"
                value={versionToAdd}
                onChange={(event) => setVersionToAdd(event.target.value)}
              />
              <select
                value={runtimeToAdd}
                onChange={(event) => setRuntimeToAdd(event.target.value)}
                className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
              >
                {runtimes.map((runtime) => (
                  <option key={runtime.runtime} value={runtime.runtime}>
                    {runtime.runtime}
                  </option>
                ))}
              </select>
              <Button onClick={handleAddVersion}>Add version</Button>
            </div>
            {runtimeError ? (
              <p className="text-sm text-destructive">{runtimeError}</p>
            ) : null}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Runtime</TableHead>
                  <TableHead>Active</TableHead>
                  <TableHead>Installed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runtimes.map((runtime) => (
                  <TableRow key={runtime.runtime}>
                    <TableCell className="font-medium uppercase">{runtime.runtime}</TableCell>
                    <TableCell>{runtime.active}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-2">
                        {runtime.installed.map((version) => (
                          <div key={version} className="flex items-center gap-1">
                            <Button
                              size="xs"
                              variant={runtime.active === version ? "default" : "outline"}
                              onClick={() => handleSetActive(runtime.runtime, version)}
                            >
                              {version}
                            </Button>
                            {runtime.active !== version ? (
                              <Button
                                size="icon-xs"
                                variant="ghost"
                                onClick={() => handleRemoveVersion(runtime.runtime, version)}
                                aria-label={`remove ${runtime.runtime} ${version}`}
                              >
                                x
                              </Button>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {!runtimeLoading && runtimes.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-center text-muted-foreground">
                      No runtimes available.
                    </TableCell>
                  </TableRow>
                ) : null}
                {runtimeLoading ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-center text-muted-foreground">
                      Loading runtimes...
                    </TableCell>
                  </TableRow>
                ) : null}
              </TableBody>
            </Table>
            <div className="flex justify-end">
              <Button variant="outline" size="sm" onClick={() => void refreshRuntimes()}>
                Refresh
              </Button>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="projects">
        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>Projects</CardTitle>
              <CardDescription>Per-project overrides</CardDescription>
            </div>
            <Input
              placeholder="Search project..."
              className="max-w-64"
              value={projectSearch}
              onChange={(event) => setProjectSearch(event.target.value)}
            />
          </CardHeader>
          <CardContent className="space-y-3">
            {filteredProjects.map((project) => (
              <div
                key={project.name}
                className="rounded-lg border bg-muted/30 p-3 transition-colors hover:bg-muted/50"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-medium">{project.name}</p>
                    <p className="text-sm text-muted-foreground">{project.path}</p>
                    <p className="text-sm text-primary">{project.domain}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline">PHP {project.php}</Badge>
                    <Badge variant="outline">Node {project.node}</Badge>
                    <Badge variant="outline">MariaDB {project.mariadb}</Badge>
                  </div>
                </div>
              </div>
            ))}
            {filteredProjects.length === 0 ? (
              <p className="text-sm text-muted-foreground">No projects match your search.</p>
            ) : null}
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}
