use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RuntimeRecord {
    pub(crate) active: String,
    pub(crate) installed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RuntimeStore {
    pub(crate) runtimes: HashMap<String, RuntimeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RuntimeResponse {
    pub(crate) runtime: String,
    pub(crate) active: String,
    pub(crate) installed: Vec<String>,
}

pub(crate) struct RuntimeState {
    pub(crate) path: PathBuf,
    pub(crate) store: RuntimeStore,
}

pub(crate) struct AppState {
    pub(crate) runtimes: Mutex<RuntimeState>,
    pub(crate) sites: Mutex<SiteState>,
    pub(crate) php: Mutex<PhpState>,
    pub(crate) mariadb: Mutex<MariaDbState>,
    pub(crate) settings: Mutex<AppSettingsState>,
    pub(crate) log_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct AppSettings {
    #[serde(rename = "autoStartServices", alias = "autoStart", default = "default_true")]
    pub(crate) auto_start_services: bool,
    #[serde(rename = "autoUpdate", default = "default_true")]
    pub(crate) auto_update: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppSettingsResponse {
    pub(crate) auto_start_services: bool,
    pub(crate) auto_update: bool,
    pub(crate) config_path: String,
}

pub(crate) struct AppSettingsState {
    pub(crate) path: PathBuf,
    pub(crate) config: AppSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiteRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) domain: String,
    pub(crate) linked: bool,
    pub(crate) ssl_enabled: bool,
    pub(crate) path: String,
    pub(crate) php_version: String,
    pub(crate) node_version: String,
    pub(crate) starter_kit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiteStore {
    pub(crate) sites: Vec<SiteRecord>,
}

pub(crate) struct SiteState {
    pub(crate) path: PathBuf,
    pub(crate) store: SiteStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiteCreateRequest {
    pub(crate) name: String,
    pub(crate) domain: String,
    pub(crate) linked: bool,
    pub(crate) ssl_enabled: bool,
    pub(crate) path: String,
    pub(crate) php_version: String,
    pub(crate) node_version: String,
    pub(crate) starter_kit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SiteDeleteRequest {
    pub(crate) site_id: String,
    pub(crate) delete_files: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SitePathInspection {
    pub(crate) exists: bool,
    pub(crate) is_directory: bool,
    pub(crate) suggested_name: Option<String>,
    pub(crate) framework: String,
    pub(crate) is_php_project: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceStatusItem {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) status: String,
    pub(crate) healthy: bool,
    pub(crate) version: String,
    pub(crate) port: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeLineRuntime {
    pub(crate) line: String,
    pub(crate) latest_version: Option<String>,
    pub(crate) installed_version: Option<String>,
    pub(crate) is_current: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeCatalogResponse {
    pub(crate) nvm_available: bool,
    pub(crate) error: Option<String>,
    pub(crate) current_version: Option<String>,
    pub(crate) installed_versions: Vec<String>,
    pub(crate) runtimes: Vec<NodeLineRuntime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct PhpConfig {
    pub(crate) base_port: u16,
    pub(crate) installed: HashMap<String, Vec<String>>,
    pub(crate) active: HashMap<String, String>,
    pub(crate) current_line: Option<String>,
    pub(crate) max_upload_size_mb: String,
    pub(crate) memory_limit_mb: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PhpLineRuntime {
    pub(crate) line: String,
    pub(crate) latest_version: Option<String>,
    pub(crate) latest_url: Option<String>,
    pub(crate) installed_versions: Vec<String>,
    pub(crate) active_version: Option<String>,
    pub(crate) fpm_port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PhpCatalogResponse {
    pub(crate) base_port: u16,
    pub(crate) max_upload_size_mb: String,
    pub(crate) memory_limit_mb: String,
    pub(crate) current_line: Option<String>,
    pub(crate) runtimes: Vec<PhpLineRuntime>,
}

pub(crate) struct PhpState {
    pub(crate) config_path: PathBuf,
    pub(crate) cache_path: PathBuf,
    pub(crate) install_dir: PathBuf,
    pub(crate) template_dir: PathBuf,
    pub(crate) config: PhpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct MariaDbConfig {
    pub(crate) port: u16,
    pub(crate) root_password: String,
    pub(crate) installed: HashMap<String, Vec<String>>,
    pub(crate) current_line: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MariaDbLineRuntime {
    pub(crate) line: String,
    pub(crate) latest_version: Option<String>,
    pub(crate) installed_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MariaDbCatalogResponse {
    pub(crate) port: u16,
    pub(crate) root_password: String,
    pub(crate) current_line: Option<String>,
    pub(crate) runtimes: Vec<MariaDbLineRuntime>,
}

pub(crate) struct MariaDbState {
    pub(crate) config_path: PathBuf,
    pub(crate) cache_path: PathBuf,
    pub(crate) install_dir: PathBuf,
    pub(crate) template_dir: PathBuf,
    pub(crate) config: MariaDbConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MariaDbReleasesCache {
    pub(crate) fetched_at_unix: u64,
    pub(crate) builds: Vec<MariaDbReleaseBuild>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MariaDbReleaseBuild {
    pub(crate) line: String,
    pub(crate) version: String,
    pub(crate) url: String,
    pub(crate) sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PhpReleaseCache {
    pub(crate) fetched_at_unix: u64,
    pub(crate) raw_json: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PhpReleaseBuild {
    pub(crate) line: String,
    pub(crate) version: String,
    pub(crate) url: String,
    pub(crate) sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BootstrapProgressEvent {
    pub(crate) phase: String,
    pub(crate) status: String,
    pub(crate) percent: Option<f64>,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogFileItem {
    pub(crate) id: String,
    pub(crate) category: String,
    pub(crate) group: String,
    pub(crate) label: String,
    pub(crate) relative_path: String,
}
