import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getServiceStatuses, type ServiceStatusItem } from "./services-api";

export function ServicesCard() {
  const [services, setServices] = useState<ServiceStatusItem[]>([]);

  useEffect(() => {
    let disposed = false;
    async function refresh() {
      try {
        const response = await getServiceStatuses();
        if (!disposed) setServices(response);
      } catch {
        if (!disposed) setServices([]);
      }
    }
    void refresh();
    return () => {
      disposed = true;
    };
  }, []);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle>Services</CardTitle>
          <CardDescription>Current local stack status</CardDescription>
        </div>
        <Button variant="outline" size="sm">
          Open logs
        </Button>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Service</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Port</TableHead>
              <TableHead>Version</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {services.map((service) => (
              <TableRow key={service.key}>
                <TableCell className="font-medium">{service.label}</TableCell>
                <TableCell>
                  <Badge variant={service.healthy ? "default" : "outline"}>
                    {service.status}
                  </Badge>
                </TableCell>
                <TableCell>{service.port}</TableCell>
                <TableCell>{service.version}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
