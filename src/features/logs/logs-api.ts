import { invoke } from "@tauri-apps/api/core";

export type LogFileItem = {
  id: string;
  category: "runtime" | "binary" | "site" | string;
  group: string;
  label: string;
  relativePath: string;
};

export async function listLogFiles(): Promise<LogFileItem[]> {
  return invoke<LogFileItem[]>("logs_list_files");
}

export async function readLogFile(relativePath: string, limit = 500): Promise<string[]> {
  return invoke<string[]>("logs_read_file", { relativePath, limit });
}
