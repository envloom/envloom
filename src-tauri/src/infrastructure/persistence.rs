use crate::domain::models::{
    AppSettings, MariaDbConfig, PhpConfig, RuntimeRecord, RuntimeResponse, RuntimeStore, SiteRecord, SiteStore,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub(crate) fn default_store() -> RuntimeStore {
    let mut runtimes = HashMap::new();
    runtimes.insert(
        "php".to_string(),
        RuntimeRecord {
            active: "8.3.6".to_string(),
            installed: vec!["7.4".to_string(), "8.1".to_string(), "8.2".to_string(), "8.3.6".to_string()],
        },
    );
    runtimes.insert(
        "node".to_string(),
        RuntimeRecord {
            active: "20.19.2".to_string(),
            installed: vec!["18".to_string(), "20.19.2".to_string(), "22".to_string()],
        },
    );
    runtimes.insert(
        "nginx".to_string(),
        RuntimeRecord {
            active: "1.27.4".to_string(),
            installed: vec!["1.25".to_string(), "1.26".to_string(), "1.27.4".to_string()],
        },
    );
    runtimes.insert(
        "mariadb".to_string(),
        RuntimeRecord {
            active: "11.4.8".to_string(),
            installed: vec!["10.11.11".to_string(), "11.4.8".to_string()],
        },
    );
    RuntimeStore { runtimes }
}

pub(crate) fn default_app_settings() -> AppSettings {
    AppSettings {
        auto_start_services: true,
        auto_update: true,
    }
}

pub(crate) fn ensure_app_settings_defaults(config: &mut AppSettings) {
    if !config.auto_start_services && !config.auto_update {
        // keep false/false if user explicitly set both off; serde default path is handled by load fallback
    }
}

pub(crate) fn load_app_settings(path: &PathBuf) -> AppSettings {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<AppSettings>(&content).unwrap_or_else(|_| default_app_settings()),
        Err(_) => default_app_settings(),
    }
}

pub(crate) fn save_app_settings(path: &PathBuf, config: &AppSettings) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create app settings dir: {e}"))?;
    }
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize app settings: {e}"))?;
    fs::write(path, content).map_err(|e| format!("failed to save app settings: {e}"))?;
    Ok(())
}

pub(crate) fn load_store(path: &PathBuf) -> RuntimeStore {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<RuntimeStore>(&content).unwrap_or_else(|_| default_store()),
        Err(_) => default_store(),
    }
}

pub(crate) fn save_store(path: &PathBuf, store: &RuntimeStore) -> Result<(), String> {
    let content =
        serde_json::to_string_pretty(store).map_err(|e| format!("failed to serialize runtime store: {e}"))?;
    fs::write(path, content).map_err(|e| format!("failed to save runtime store: {e}"))?;
    Ok(())
}

pub(crate) fn sorted_response(store: &RuntimeStore) -> Vec<RuntimeResponse> {
    let mut out: Vec<RuntimeResponse> = store
        .runtimes
        .iter()
        .map(|(runtime, record)| RuntimeResponse {
            runtime: runtime.clone(),
            active: record.active.clone(),
            installed: record.installed.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.runtime.cmp(&b.runtime));
    out
}

pub(crate) fn default_sites_store() -> SiteStore {
    SiteStore { sites: vec![] }
}

pub(crate) fn load_sites_store(path: &PathBuf) -> SiteStore {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<SiteStore>(&content).unwrap_or_else(|_| default_sites_store()),
        Err(_) => default_sites_store(),
    }
}

pub(crate) fn save_sites_store(path: &PathBuf, store: &SiteStore) -> Result<(), String> {
    let content = serde_json::to_string_pretty(store)
        .map_err(|e| format!("failed to serialize sites store: {e}"))?;
    fs::write(path, content).map_err(|e| format!("failed to save sites store: {e}"))?;
    Ok(())
}

pub(crate) fn sorted_sites(store: &SiteStore) -> Vec<SiteRecord> {
    let mut out = store.sites.clone();
    out.sort_by(|a, b| a.domain.to_lowercase().cmp(&b.domain.to_lowercase()));
    out
}

pub(crate) fn default_php_config() -> PhpConfig {
    PhpConfig {
        base_port: 9000,
        installed: HashMap::new(),
        active: HashMap::new(),
        current_line: None,
        max_upload_size_mb: "128".to_string(),
        memory_limit_mb: "512".to_string(),
    }
}

pub(crate) fn default_mariadb_config() -> MariaDbConfig {
    MariaDbConfig {
        port: 3306,
        root_password: String::new(),
        installed: HashMap::new(),
        current_line: None,
    }
}

pub(crate) fn ensure_php_config_defaults(config: &mut PhpConfig) {
    if config.base_port == 0 {
        config.base_port = 9000;
    }
    if config.max_upload_size_mb.trim().is_empty() {
        config.max_upload_size_mb = "128".to_string();
    }
    if config.memory_limit_mb.trim().is_empty() {
        config.memory_limit_mb = "512".to_string();
    }
}

pub(crate) fn ensure_mariadb_config_defaults(config: &mut MariaDbConfig) {
    if config.port == 0 {
        config.port = 3306;
    }
}

pub(crate) fn load_php_config(path: &PathBuf) -> PhpConfig {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<PhpConfig>(&content).unwrap_or_else(|_| default_php_config()),
        Err(_) => default_php_config(),
    }
}

pub(crate) fn load_mariadb_config(path: &PathBuf) -> MariaDbConfig {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str::<MariaDbConfig>(&content).unwrap_or_else(|_| default_mariadb_config()),
        Err(_) => default_mariadb_config(),
    }
}

pub(crate) fn save_php_config(path: &PathBuf, config: &PhpConfig) -> Result<(), String> {
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize php config: {e}"))?;
    fs::write(path, content).map_err(|e| format!("failed to save php config: {e}"))?;
    Ok(())
}

pub(crate) fn save_mariadb_config(path: &PathBuf, config: &MariaDbConfig) -> Result<(), String> {
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| format!("failed to serialize mariadb config: {e}"))?;
    fs::write(path, content).map_err(|e| format!("failed to save mariadb config: {e}"))?;
    Ok(())
}
