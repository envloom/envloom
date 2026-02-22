import { invoke, isTauri } from "@tauri-apps/api/core";

export type ServiceStatusItem = {
  key: string;
  label: string;
  status: string;
  healthy: boolean;
  version: string;
  port: string;
};

export async function getServiceStatuses(): Promise<ServiceStatusItem[]> {
  if (!isTauri()) return [];
  return invoke<ServiceStatusItem[]>("get_service_statuses");
}

export async function startAllServices(): Promise<ServiceStatusItem[]> {
  if (!isTauri()) return [];
  return invoke<ServiceStatusItem[]>("services_start_all");
}

export async function stopAllServices(): Promise<ServiceStatusItem[]> {
  if (!isTauri()) return [];
  return invoke<ServiceStatusItem[]>("services_stop_all");
}
