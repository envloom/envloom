use serde_json::Value;
use sha2::{Digest, Sha256};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{
    fs::File,
    io::{Read, Write},
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
mod domain;
mod infrastructure;
use zip::ZipArchive;

use crate::domain::models::*;
use crate::infrastructure::logging::append_runtime_log;
use crate::infrastructure::persistence::{
    ensure_app_settings_defaults, ensure_mariadb_config_defaults, ensure_php_config_defaults, load_app_settings,
    load_mariadb_config, load_php_config,
    load_sites_store, load_store, save_mariadb_config, save_php_config, save_sites_store, save_store, sorted_response,
    sorted_sites, save_app_settings,
};

const PHP_RELEASES_URL: &str = "https://windows.php.net/downloads/releases/releases.json";
const RUNTIME_RELEASES_CACHE_SECONDS: u64 = 3_600;
const RUNTIME_UPDATE_CHECK_INTERVAL_SECONDS: u64 = 3_600;
const NGINX_RELEASES_URL: &str = "https://api.github.com/repos/nginx/nginx/releases";
const MARIADB_RELEASES_URL: &str = "https://downloads.mariadb.org/rest-api/mariadb/";
static SHUTDOWN_STOP_TRIGGERED: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn envloom_global_config_path() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".envloom").join("config.json")
}

fn app_settings_response(path: &Path, config: &AppSettings) -> AppSettingsResponse {
    AppSettingsResponse {
        auto_start_services: config.auto_start_services,
        auto_update: config.auto_update,
        config_path: path.to_string_lossy().to_string(),
    }
}

fn normalize_mb_value(raw: &str, allow_unlimited: bool) -> String {
    let value = raw.trim();
    if allow_unlimited && value == "-1" {
        return "-1".to_string();
    }
    let digits_only = value.chars().all(|c| c.is_ascii_digit());
    if digits_only && !value.is_empty() {
        return value.to_string();
    }
    value
        .trim_end_matches('M')
        .trim_end_matches('m')
        .trim()
        .to_string()
}

fn ensure_php_template_files(template_dir: &Path) -> Result<(), String> {
    let php_dir = template_dir.join("php");
    let mariadb_dir = template_dir.join("mariadb");
    fs::create_dir_all(&php_dir).map_err(|e| format!("failed to create php template dir: {e}"))?;
    fs::create_dir_all(&mariadb_dir).map_err(|e| format!("failed to create mariadb template dir: {e}"))?;

    let php_ini = php_dir.join("php.ini");
    if !php_ini.exists() {
        fs::write(
            &php_ini,
            "; Envloom base php.ini template\n[PHP]\nengine = On\n",
        )
        .map_err(|e| format!("failed to create base php.ini template: {e}"))?;
    }

    let mariadb_cfg = mariadb_dir.join("my.cnf");
    if !mariadb_cfg.exists() {
        fs::write(
            &mariadb_cfg,
            "# Envloom base mariadb config\n[mariadb]\nport=3306\n",
        )
        .map_err(|e| format!("failed to create base my.cnf template: {e}"))?;
    }
    Ok(())
}

fn write_mariadb_template(template_dir: &Path, logs_dir: &Path, config: &MariaDbConfig) -> Result<(), String> {
    ensure_php_template_files(template_dir)?;
    let mariadb_cfg = template_dir.join("mariadb").join("my.cnf");
    let mariadb_logs_dir = logs_dir.join("mariadb");
    fs::create_dir_all(&mariadb_logs_dir).map_err(|e| format!("failed to create mariadb logs dir: {e}"))?;
    let log_error = mariadb_logs_dir.join("mariadb.error.log").to_string_lossy().replace('\\', "/");
    let general_log_file = mariadb_logs_dir.join("mariadb.general.log").to_string_lossy().replace('\\', "/");
    let slow_log_file = mariadb_logs_dir.join("mariadb.slow.log").to_string_lossy().replace('\\', "/");
    let content = format!(
        "# Envloom MariaDB config\n[mariadb]\nport={}\nbind-address=127.0.0.1\nlog_error={}\ngeneral_log=1\ngeneral_log_file={}\nslow_query_log=1\nslow_query_log_file={}\n\n[client]\nuser=root\npassword={}\n",
        config.port, log_error, general_log_file, slow_log_file, config.root_password
    );
    let current = fs::read_to_string(&mariadb_cfg).unwrap_or_default();
    if current != content {
        fs::write(mariadb_cfg, content).map_err(|e| format!("failed to write mariadb template: {e}"))?;
    }
    Ok(())
}

fn apply_mariadb_config_to_line(
    install_dir: &Path,
    template_dir: &Path,
    line: &str,
    config: &MariaDbConfig,
) -> Result<(), String> {
    let line_dir = install_dir.join(line);
    if !line_dir.exists() {
        return Ok(());
    }
    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.to_path_buf());
    let logs_dir = resolve_logs_dir_from_bin_root(&bin_root);
    write_mariadb_template(template_dir, &logs_dir, config)?;
    let source = template_dir.join("mariadb").join("my.cnf");
    let target = line_dir.join("my.ini");
    let next = fs::read_to_string(source).map_err(|e| format!("failed reading mariadb template: {e}"))?;
    let current = fs::read_to_string(&target).unwrap_or_default();
    if current != next {
        fs::write(target, next).map_err(|e| format!("failed writing runtime my.ini: {e}"))?;
    }
    Ok(())
}

fn apply_mariadb_config_to_installed(
    install_dir: &Path,
    template_dir: &Path,
    config: &MariaDbConfig,
) -> Result<(), String> {
    for line in config.installed.keys() {
        apply_mariadb_config_to_line(install_dir, template_dir, line, config)?;
    }
    Ok(())
}

fn managed_php_ini_block(config: &PhpConfig) -> String {
    let upload = normalize_mb_value(&config.max_upload_size_mb, false);
    let memory = normalize_mb_value(&config.memory_limit_mb, true);
    let memory_render = if memory == "-1" {
        "-1".to_string()
    } else {
        format!("{memory}M")
    };
    format!("upload_max_filesize = {upload}M\npost_max_size = {upload}M\nmemory_limit = {memory_render}\n")
}

fn required_php_ini_block() -> String {
    [
        "[PHP]",
        "extension_dir = \"ext\"",
        "extension=pdo_sqlite",
        "extension=sqlite3",
        "extension=pdo_mysql",
        "extension=pdo_pgsql",
        "extension=pdo_odbc",
        "extension=openssl",
        "extension=curl",
        "extension=mbstring",
        "extension=fileinfo",
        "",
    ]
    .join("\n")
}

fn upsert_required_php_block(content: &str) -> String {
    const START: &str = "; --- Envloom required extensions ---";
    const END: &str = "; --- /Envloom required extensions ---";
    let block = format!("{START}\n{}{}\n", required_php_ini_block(), END);
    if let Some(start_idx) = content.find(START) {
        if let Some(end_rel) = content[start_idx..].find(END) {
            let end_idx = start_idx + end_rel + END.len();
            let mut out = String::new();
            out.push_str(content[..start_idx].trim_end());
            out.push_str("\n\n");
            out.push_str(&block);
            out.push_str(content[end_idx..].trim_start_matches('\n'));
            return out;
        }
    }
    let mut out = content.trim_end().to_string();
    out.push_str("\n\n");
    out.push_str(&block);
    out
}

fn upsert_managed_block(content: &str, config: &PhpConfig) -> String {
    const START: &str = "; --- Envloom managed values ---";
    const END: &str = "; --- /Envloom managed values ---";
    let block = format!("{}\n{}{}\n", START, managed_php_ini_block(config), END);
    if let Some(start_idx) = content.find(START) {
        if let Some(end_rel) = content[start_idx..].find(END) {
            let end_idx = start_idx + end_rel + END.len();
            let mut out = String::new();
            out.push_str(content[..start_idx].trim_end());
            out.push_str("\n\n");
            out.push_str(&block);
            out.push_str(content[end_idx..].trim_start_matches('\n'));
            return out;
        }
    }
    let mut out = content.trim_end().to_string();
    out.push_str("\n\n");
    out.push_str(&block);
    out
}

fn write_base_php_template(template_dir: &Path, config: &PhpConfig) -> Result<(), String> {
    ensure_php_template_files(template_dir)?;
    let base_path = template_dir.join("php").join("php.ini");
    let current = fs::read_to_string(&base_path).map_err(|e| format!("failed reading base php.ini: {e}"))?;
    let with_required = upsert_required_php_block(&current);
    let next = upsert_managed_block(&with_required, config);
    if current != next {
        fs::write(base_path, next).map_err(|e| format!("failed writing base php.ini: {e}"))?;
    }
    Ok(())
}

fn ensure_php_line_template(template_dir: &Path, line: &str) -> Result<PathBuf, String> {
    let line_path = template_dir.join("php").join(format!("{line}.ini"));
    if !line_path.exists() {
        fs::write(&line_path, format!("; Envloom overrides for PHP {line}\n"))
            .map_err(|e| format!("failed to create line php template: {e}"))?;
    }
    Ok(line_path)
}

fn render_php_ini(template_dir: &Path, line: &str, config: &PhpConfig) -> Result<String, String> {
    ensure_php_template_files(template_dir)?;
    write_base_php_template(template_dir, config)?;
    let base_path = template_dir.join("php").join("php.ini");
    let line_path = ensure_php_line_template(template_dir, line)?;
    let base = fs::read_to_string(base_path).map_err(|e| format!("failed reading base php.ini: {e}"))?;
    let line_override =
        fs::read_to_string(line_path).map_err(|e| format!("failed reading version php.ini: {e}"))?;
    let rendered = format!("{base}\n\n; --- Envloom version override ({line}) ---\n{line_override}\n");
    Ok(rendered)
}

fn upsert_php_runtime_log_block(content: &str, error_log_path: &Path) -> String {
    const START: &str = "; --- Envloom runtime logging ---";
    const END: &str = "; --- /Envloom runtime logging ---";
    let error_log = error_log_path.to_string_lossy().replace('\\', "/");
    let block = format!(
        "{START}\nlog_errors = On\nerror_log = \"{error_log}\"\n{END}\n"
    );
    if let Some(start_idx) = content.find(START) {
        if let Some(end_rel) = content[start_idx..].find(END) {
            let end_idx = start_idx + end_rel + END.len();
            let mut out = String::new();
            out.push_str(content[..start_idx].trim_end());
            out.push_str("\n\n");
            out.push_str(&block);
            out.push_str(content[end_idx..].trim_start_matches('\n'));
            return out;
        }
    }
    let mut out = content.trim_end().to_string();
    out.push_str("\n\n");
    out.push_str(&block);
    out
}

fn apply_php_ini_to_line(
    install_dir: &Path,
    template_dir: &Path,
    line: &str,
    config: &PhpConfig,
) -> Result<(), String> {
    let line_dir = install_dir.join(line);
    if !line_dir.exists() {
        return Ok(());
    }
    let php_ini_path = line_dir.join("php.ini");
    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.to_path_buf());
    let php_logs_dir = resolve_logs_dir_from_bin_root(&bin_root).join("php");
    fs::create_dir_all(&php_logs_dir).map_err(|e| format!("failed to create php logs dir: {e}"))?;
    let php_error_log_path = php_logs_dir.join(format!("php-{}.error.log", line.replace('.', "_")));
    let rendered = render_php_ini(template_dir, line, config)?;
    let content = upsert_php_runtime_log_block(&rendered, &php_error_log_path);
    let current = fs::read_to_string(&php_ini_path).unwrap_or_default();
    if current != content {
        fs::write(php_ini_path, content).map_err(|e| format!("failed to write runtime php.ini: {e}"))?;
    }
    Ok(())
}

fn apply_php_ini_to_installed(
    install_dir: &Path,
    template_dir: &Path,
    config: &PhpConfig,
) -> Result<(), String> {
    for line in config.installed.keys() {
        apply_php_ini_to_line(install_dir, template_dir, line, config)?;
    }
    Ok(())
}

fn line_port(base_port: u16, line: &str) -> u16 {
    let parts: Vec<u16> = line
        .split('.')
        .filter_map(|part| part.parse::<u16>().ok())
        .collect();
    if parts.len() != 2 {
        return base_port;
    }
    base_port.saturating_add(parts[0] * 10 + parts[1])
}

fn is_local_tcp_port_open(port: u16) -> bool {
    let addr = format!("127.0.0.1:{port}");
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(sock) = addrs.next() {
            return TcpStream::connect_timeout(&sock, std::time::Duration::from_millis(300)).is_ok();
        }
    }
    false
}

fn is_php_cgi_listening_in_root(_install_dir: &Path, port: u16) -> bool {
    is_local_tcp_port_open(port)
}

fn stop_php_fpm_services(install_dir: &Path) -> Result<(), String> {
    let install_root = install_dir.to_string_lossy().replace('\'', "''");
    let stop_script = format!(
        "$root='{root}'; \
         Get-Process -Name 'php-cgi' -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath -like ($root + '*') }} | \
         ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}",
        root = install_root
    );
    let _ = run_powershell(&stop_script)?;
    Ok(())
}

fn restart_php_fpm_services(install_dir: &Path, config: &PhpConfig) -> Result<(), String> {
    let _ = stop_php_fpm_services(install_dir);
    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.to_path_buf());
    let logs_dir = resolve_logs_dir_from_bin_root(&bin_root).join("php");
    fs::create_dir_all(&logs_dir).map_err(|e| format!("failed to create php logs dir: {e}"))?;

    let mut failures: Vec<String> = Vec::new();
    for line in config.installed.keys() {
        let line_dir = install_dir.join(line);
        if !line_dir.exists() {
            continue;
        }
        let php_cgi = line_dir.join("php-cgi.exe");
        let php_ini = line_dir.join("php.ini");
        if !php_cgi.exists() || !php_ini.exists() {
            continue;
        }
        let port = line_port(config.base_port, line);
        let php_error_log = logs_dir
            .join(format!("php-{}.error.log", line.replace('.', "_")))
            .to_string_lossy()
            .replace('\\', "/");
        let start_script = format!(
            "Start-Process -WindowStyle Hidden -FilePath '{exe}' -WorkingDirectory '{cwd}' -ArgumentList '-b','{port}','-c','{ini}','-d','log_errors=On','-d','error_log={php_error_log}' | Out-Null",
            exe = ps_quote(&php_cgi.to_string_lossy()),
            cwd = ps_quote(&line_dir.to_string_lossy()),
            ini = ps_quote(&php_ini.to_string_lossy()),
            port = port,
            php_error_log = ps_quote(&php_error_log)
        );
        if let Err(e) = run_powershell(&start_script) {
            failures.push(format!("php {line} start failed: {e}"));
            continue;
        }
        let mut ok = false;
        for _ in 0..12 {
            if is_php_cgi_listening_in_root(install_dir, port) {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if !ok {
            failures.push(format!("php {line} did not bind on 127.0.0.1:{port}"));
        }
    }
    if !failures.is_empty() {
        return Err(failures.join(" | "));
    }

    Ok(())
}

fn parse_version_parts(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect()
}

fn is_version_gt(a: &str, b: &str) -> bool {
    let av = parse_version_parts(a);
    let bv = parse_version_parts(b);
    let max_len = av.len().max(bv.len());
    for idx in 0..max_len {
        let ai = *av.get(idx).unwrap_or(&0);
        let bi = *bv.get(idx).unwrap_or(&0);
        if ai > bi {
            return true;
        }
        if ai < bi {
            return false;
        }
    }
    false
}

fn run_powershell(script: &str) -> Result<String, String> {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd
        .output()
        .map_err(|e| format!("failed to execute powershell: {e}"))?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "powershell command failed (exit {code}). stdout: {stdout}. stderr: {stderr}"
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn extract_zip_file(zip_path: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|e| format!("failed to create extract dir: {e}"))?;
    let file = File::open(zip_path).map_err(|e| format!("failed to open zip: {e}"))?;
    let mut archive = ZipArchive::new(file).map_err(|e| format!("failed to read zip archive: {e}"))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("failed to read zip entry #{i}: {e}"))?;
        let Some(name) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            continue;
        };
        let out_path = destination.join(name);
        if entry.is_dir() {
            fs::create_dir_all(&out_path).map_err(|e| format!("failed to create dir from zip: {e}"))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create zip parent dir: {e}"))?;
        }
        let mut out = File::create(&out_path).map_err(|e| format!("failed to create extracted file: {e}"))?;
        std::io::copy(&mut entry, &mut out).map_err(|e| format!("failed to extract zip entry: {e}"))?;
    }
    Ok(())
}

fn latest_nvm_windows_setup_asset() -> Result<(String, String), String> {
    let raw = get_json_with_user_agent(
        "https://api.github.com/repos/coreybutler/nvm-windows/releases/latest",
        "Envloom/0.1.0",
    )?;
    let value: Value = serde_json::from_str(&raw).map_err(|e| format!("failed to parse nvm release json: {e}"))?;
    let version = value
        .get("tag_name")
        .and_then(Value::as_str)
        .unwrap_or("latest")
        .to_string();
    let assets = value
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| "nvm latest release has no assets".to_string())?;
    for asset in assets {
        let name = asset.get("name").and_then(Value::as_str).unwrap_or("").to_lowercase();
        if name == "nvm-setup.exe" {
            let url = asset
                .get("browser_download_url")
                .and_then(Value::as_str)
                .ok_or_else(|| "nvm setup asset missing browser_download_url".to_string())?;
            return Ok((version, url.to_string()));
        }
    }
    Err("nvm-setup.exe not found in latest nvm-windows release".to_string())
}

fn install_nvm_windows_silently(bin_root: &Path) -> Result<String, String> {
    let (version, url) = latest_nvm_windows_setup_asset()?;
    let downloads = shared_downloads_dir(bin_root);
    fs::create_dir_all(&downloads).map_err(|e| format!("failed to create downloads dir: {e}"))?;
    let installer_path = downloads.join("nvm-setup.exe");
    if installer_path.exists() {
        let _ = fs::remove_file(&installer_path);
    }
    download_with_progress(&url, &installer_path, |_| {})?;

    let mut cmd = Command::new(&installer_path);
    cmd.args(["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd
        .output()
        .map_err(|e| format!("failed to execute nvm installer: {e}"))?;
    let _ = fs::remove_file(&installer_path);
    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "nvm installer failed (exit {code}). stdout: {stdout}. stderr: {stderr}"
        ));
    }
    Ok(version)
}

fn detect_framework_from_path(path: &Path) -> (String, bool) {
    let composer_json = path.join("composer.json");
    let artisan = path.join("artisan");
    let symfony_console = path.join("bin").join("console");
    let wp_config = path.join("wp-config.php");
    let index_php = path.join("index.php");

    if artisan.exists() {
        return ("laravel".to_string(), true);
    }
    if symfony_console.exists() {
        return ("symfony".to_string(), true);
    }
    if wp_config.exists() || path.join("wp-includes").exists() {
        return ("wordpress".to_string(), true);
    }
    if composer_json.exists() {
        if let Ok(raw) = fs::read_to_string(&composer_json) {
            if let Ok(value) = serde_json::from_str::<Value>(&raw) {
                let requires = value
                    .get("require")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                if requires.contains_key("laravel/framework") {
                    return ("laravel".to_string(), true);
                }
                if requires.keys().any(|k| k.starts_with("symfony/")) {
                    return ("symfony".to_string(), true);
                }
                return ("php-composer".to_string(), true);
            }
        }
    }
    if index_php.exists() {
        return ("php-simple".to_string(), true);
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|v| v.to_str()).unwrap_or_default().eq_ignore_ascii_case("php") {
                return ("php-simple".to_string(), true);
            }
        }
    }
    ("unknown".to_string(), false)
}

fn run_command_capture(
    executable: &Path,
    args: &[String],
    working_dir: Option<&Path>,
) -> Result<String, String> {
    let mut command = Command::new(executable);
    command.args(args);
    if let Some(dir) = working_dir {
        command.current_dir(dir);
    }
    let output = command
        .output()
        .map_err(|e| format!("failed to execute {}: {e}", executable.to_string_lossy()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        return Err(format!(
            "command failed (exit {code}): {} {} | stdout: {} | stderr: {}",
            executable.to_string_lossy(),
            args.join(" "),
            stdout,
            stderr
        ));
    }
    if !stderr.is_empty() {
        Ok(format!("{stdout}\n{stderr}"))
    } else {
        Ok(stdout)
    }
}

fn emit_site_provision_output(app: &tauri::AppHandle, line: &str) {
    let _ = app.emit("site-provision-output", line.to_string());
}

fn run_command_capture_report(
    app: &tauri::AppHandle,
    label: &str,
    executable: &Path,
    args: &[String],
    working_dir: Option<&Path>,
) -> Result<String, String> {
    emit_site_provision_output(
        app,
        &format!("$ {} {}", executable.to_string_lossy(), args.join(" ")),
    );
    let output = run_command_capture(executable, args, working_dir)?;
    if output.trim().is_empty() {
        emit_site_provision_output(app, &format!("[{label}] done"));
    } else {
        for line in output.lines() {
            emit_site_provision_output(app, line);
        }
    }
    Ok(output)
}

fn normalize_starter_kit(value: Option<&str>) -> Option<String> {
    let raw = value?.trim().to_lowercase();
    if raw.is_empty() || raw == "none" || raw == "no starter kit" {
        return None;
    }
    Some(raw)
}

fn starter_repo_url(value: &str) -> Option<&'static str> {
    match value {
        "react" => Some("https://github.com/laravel/react-starter-kit.git"),
        "vue" => Some("https://github.com/laravel/vue-starter-kit.git"),
        "svelte" => Some("https://github.com/laravel/svelte-starter-kit.git"),
        "livewire" => Some("https://github.com/laravel/livewire-starter-kit.git"),
        _ => None,
    }
}

fn ensure_env_file(project_path: &Path) -> Result<bool, String> {
    let env_path = project_path.join(".env");
    if env_path.exists() {
        return Ok(false);
    }
    let env_example = project_path.join(".env.example");
    if env_example.exists() {
        let content = fs::read(&env_example).map_err(|e| format!("failed to read .env.example: {e}"))?;
        fs::write(&env_path, content).map_err(|e| format!("failed to create .env from .env.example: {e}"))?;
        return Ok(true);
    }
    Ok(false)
}

fn ensure_sqlite_database_file(project_path: &Path) -> Result<(), String> {
    let db_dir = project_path.join("database");
    if !db_dir.exists() {
        return Ok(());
    }
    let sqlite = db_dir.join("database.sqlite");
    if !sqlite.exists() {
        File::create(&sqlite).map_err(|e| format!("failed to create sqlite database file: {e}"))?;
    }
    Ok(())
}

fn provision_new_laravel_site(
    app: &tauri::AppHandle,
    php_install_dir: &Path,
    project_path: &Path,
    php_line: &str,
    starter_kit: Option<&str>,
) -> Result<(), String> {
    let php_exe = php_install_dir.join(php_line).join("php.exe");
    if !php_exe.exists() {
        return Err(format!(
            "selected PHP {} is not installed. Install it first in Runtime > PHP.",
            php_line
        ));
    }

    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.to_path_buf());
    let composer_phar = bin_root.join("composer").join("composer.phar");
    if !composer_phar.exists() {
        return Err("composer.phar is missing. Wait for bootstrap or download Composer first.".to_string());
    }

    let parent = project_path
        .parent()
        .ok_or_else(|| "invalid target directory".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("failed to create parent directory: {e}"))?;
    if project_path.exists() {
        let is_empty = fs::read_dir(project_path)
            .map_err(|e| format!("failed to inspect target directory: {e}"))?
            .next()
            .is_none();
        if !is_empty {
            return Err(format!(
                "target directory is not empty: {}",
                project_path.to_string_lossy()
            ));
        }
    }

    let starter = normalize_starter_kit(starter_kit);
    if let Some(ref starter_value) = starter {
        let Some(repo_url) = starter_repo_url(starter_value) else {
            return Err(format!("unsupported starter kit: {starter_value}"));
        };
        let clone_args = vec![
            "clone".to_string(),
            "--depth".to_string(),
            "1".to_string(),
            repo_url.to_string(),
            project_path.to_string_lossy().to_string(),
        ];
        let _ = run_command_capture_report(app, "git.clone", Path::new("git"), &clone_args, Some(parent))?;
    } else {
        let create_args = vec![
            composer_phar.to_string_lossy().to_string(),
            "create-project".to_string(),
            "laravel/laravel".to_string(),
            project_path.to_string_lossy().to_string(),
            "--no-interaction".to_string(),
        ];
        let _ = run_command_capture_report(app, "composer.create", &php_exe, &create_args, Some(parent))?;
    }

    let env_copied = ensure_env_file(project_path)?;
    emit_site_provision_output(
        app,
        if env_copied {
            "Action: copied .env from .env.example"
        } else {
            "Action: .env already present"
        },
    );
    ensure_sqlite_database_file(project_path)?;

    let composer_install_args = vec![
        composer_phar.to_string_lossy().to_string(),
        "install".to_string(),
        "--no-interaction".to_string(),
    ];
    let _ =
        run_command_capture_report(app, "composer.install", &php_exe, &composer_install_args, Some(project_path))?;

    let key_generate_args = vec![
        "artisan".to_string(),
        "key:generate".to_string(),
        "--force".to_string(),
        "--no-interaction".to_string(),
    ];
    let _ = run_command_capture_report(app, "artisan.key", &php_exe, &key_generate_args, Some(project_path))?;

    let migrate_first_args = vec![
        "artisan".to_string(),
        "migrate".to_string(),
        "--force".to_string(),
        "--no-interaction".to_string(),
    ];
    let _ = run_command_capture_report(app, "artisan.migrate", &php_exe, &migrate_first_args, Some(project_path))?;

    let boost_require_args = vec![
        composer_phar.to_string_lossy().to_string(),
        "require".to_string(),
        "laravel/boost".to_string(),
        "--no-interaction".to_string(),
    ];
    let _ = run_command_capture_report(app, "composer.boost", &php_exe, &boost_require_args, Some(project_path))?;

    let boost_install_args = vec![
        "artisan".to_string(),
        "boost:install".to_string(),
        "--no-interaction".to_string(),
    ];
    let _ = run_command_capture_report(app, "artisan.boost", &php_exe, &boost_install_args, Some(project_path))?;

    let npm_install_args = vec!["/C".to_string(), "npm install".to_string()];
    match run_command_capture_report(app, "npm.install", Path::new("cmd"), &npm_install_args, Some(project_path)) {
        Ok(_) => {}
        Err(first_error) => {
            emit_site_provision_output(
                app,
                &format!("npm install failed, retrying with --legacy-peer-deps: {first_error}"),
            );
            let npm_retry_args = vec!["/C".to_string(), "npm install --legacy-peer-deps".to_string()];
            let _ = run_command_capture_report(
                app,
                "npm.install.retry",
                Path::new("cmd"),
                &npm_retry_args,
                Some(project_path),
            )?;
        }
    }

    let npm_build_args = vec!["/C".to_string(), "npm run build".to_string()];
    let _ = run_command_capture_report(app, "npm.build", Path::new("cmd"), &npm_build_args, Some(project_path))?;

    let migrate_second_args = vec![
        "artisan".to_string(),
        "migrate".to_string(),
        "--force".to_string(),
        "--no-interaction".to_string(),
    ];
    let _ =
        run_command_capture_report(app, "artisan.migrate.final", &php_exe, &migrate_second_args, Some(project_path))?;

    Ok(())
}

fn run_nvm_command(args: &[&str]) -> Result<String, String> {
    let joined = args.join(" ");
    let script = format!("nvm {joined}");
    run_powershell(&script)
}

fn nvm_is_available() -> bool {
    run_nvm_command(&["version"]).is_ok()
}

fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn nvm_symlink_path() -> Option<String> {
    let script = "$symlink = $env:NVM_SYMLINK; if (-not $symlink) { \
        $home = $env:NVM_HOME; \
        if (-not $home) { $home = Join-Path $env:APPDATA 'nvm' } \
        $settings = Join-Path $home 'settings.txt'; \
        if (Test-Path -LiteralPath $settings) { \
          $line = Get-Content -LiteralPath $settings | Where-Object { $_ -match '^\\s*path\\s*:\\s*' } | Select-Object -First 1; \
          if ($line) { $symlink = ($line -replace '^\\s*path\\s*:\\s*','').Trim() } \
        } \
      } \
      if ($symlink) { $symlink }";
    run_powershell(script).ok().and_then(|output| {
        let value = output.trim().replace('\\', "/");
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

fn ensure_runtime_shims(bin_root: &Path) -> Result<PathBuf, String> {
    let shims_dir = bin_root.to_path_buf();
    fs::create_dir_all(&shims_dir).map_err(|e| format!("failed to create bin dir for shims: {e}"))?;
    let mut managed_shims: HashSet<String> = HashSet::new();

    let nginx_cmd = shims_dir.join("nginx.cmd");
    let nginx_cmd_content = "@ECHO OFF\r\nset \"Envloom_NGINX_DIR=%~dp0nginx\\current\"\r\n\"%Envloom_NGINX_DIR%\\nginx.exe\" -p \"%Envloom_NGINX_DIR%\" %*\r\n";
    let current = fs::read_to_string(&nginx_cmd).unwrap_or_default();
    if current != nginx_cmd_content {
        fs::write(&nginx_cmd, nginx_cmd_content)
            .map_err(|e| format!("failed to write nginx shim: {e}"))?;
    }
    managed_shims.insert("nginx.cmd".to_string());

    let composer_cmd = shims_dir.join("composer.cmd");
    let composer_cmd_content = "@ECHO OFF\r\nphp \"%~dp0composer\\composer.phar\" %*\r\n";
    let current = fs::read_to_string(&composer_cmd).unwrap_or_default();
    if current != composer_cmd_content {
        fs::write(&composer_cmd, composer_cmd_content)
            .map_err(|e| format!("failed to write composer shim: {e}"))?;
    }
    managed_shims.insert("composer.cmd".to_string());
    let legacy_composer_bat = bin_root.join("composer").join("composer.bat");
    if legacy_composer_bat.exists() {
        let _ = fs::remove_file(legacy_composer_bat);
    }

    let php_current_shim = shims_dir.join("php.cmd");
    let php_current_content = "@ECHO OFF\r\n\"%~dp0php\\current\\php.exe\" %*\r\n";
    let current = fs::read_to_string(&php_current_shim).unwrap_or_default();
    if current != php_current_content {
        fs::write(&php_current_shim, php_current_content)
            .map_err(|e| format!("failed to write php current shim: {e}"))?;
    }
    managed_shims.insert("php.cmd".to_string());

    let php_root = bin_root.join("php");
    if let Ok(entries) = fs::read_dir(&php_root) {
        for entry in entries {
            let entry = match entry {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let line = match path.file_name().and_then(|name| name.to_str()) {
                Some(value) => value.to_string(),
                None => continue,
            };
            if line == "current" || line.starts_with('_') {
                continue;
            }
            if !path.join("php.exe").exists() {
                continue;
            }
            let mut parts = line.split('.');
            let major = parts.next().unwrap_or_default();
            let minor = parts.next().unwrap_or_default();
            if major.is_empty()
                || minor.is_empty()
                || parts.next().is_some()
                || !major.chars().all(|c| c.is_ascii_digit())
                || !minor.chars().all(|c| c.is_ascii_digit())
            {
                continue;
            }
            let shim_name = format!("php{major}{minor}.cmd");
            let shim_path = shims_dir.join(&shim_name);
            let shim_content = format!("@ECHO OFF\r\n\"%~dp0php\\{line}\\php.exe\" %*\r\n");
            let current = fs::read_to_string(&shim_path).unwrap_or_default();
            if current != shim_content {
                fs::write(&shim_path, shim_content)
                    .map_err(|e| format!("failed to write php shim '{shim_name}': {e}"))?;
            }
            managed_shims.insert(shim_name);
        }
    }

    let mariadb_shims = [("mariadb.cmd", "mariadb.exe"), ("mysql.cmd", "mysql.exe")];
    for (shim_name, exe_name) in mariadb_shims {
        let exe_path = bin_root.join("mariadb").join("current").join("bin").join(exe_name);
        if !exe_path.exists() {
            continue;
        }
        let shim_path = shims_dir.join(shim_name);
        let shim_content = format!("@ECHO OFF\r\n\"%~dp0mariadb\\current\\bin\\{exe_name}\" %*\r\n");
        let current = fs::read_to_string(&shim_path).unwrap_or_default();
        if current != shim_content {
            fs::write(&shim_path, shim_content)
                .map_err(|e| format!("failed to write mariadb shim '{shim_name}': {e}"))?;
        }
        managed_shims.insert(shim_name.to_string());
    }

    let mariadb_root = bin_root.join("mariadb");
    if let Ok(entries) = fs::read_dir(&mariadb_root) {
        for entry in entries {
            let entry = match entry {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let line = match path.file_name().and_then(|name| name.to_str()) {
                Some(value) => value.to_string(),
                None => continue,
            };
            if line == "current" || line.starts_with('_') {
                continue;
            }
            let mut parts = line.split('.');
            let major = parts.next().unwrap_or_default();
            let minor = parts.next().unwrap_or_default();
            if major.is_empty()
                || minor.is_empty()
                || parts.next().is_some()
                || !major.chars().all(|c| c.is_ascii_digit())
                || !minor.chars().all(|c| c.is_ascii_digit())
            {
                continue;
            }
            let suffix = format!("{major}{minor}");
            for (prefix, exe_name) in [("mysql", "mysql.exe"), ("mariadb", "mariadb.exe")] {
                let exe_path = path.join("bin").join(exe_name);
                if !exe_path.exists() {
                    continue;
                }
                let shim_name = format!("{prefix}{suffix}.cmd");
                let shim_path = shims_dir.join(&shim_name);
                let shim_content = format!("@ECHO OFF\r\n\"%~dp0mariadb\\{line}\\bin\\{exe_name}\" %*\r\n");
                let current = fs::read_to_string(&shim_path).unwrap_or_default();
                if current != shim_content {
                    fs::write(&shim_path, shim_content).map_err(|e| {
                        format!("failed to write mariadb versioned shim '{shim_name}': {e}")
                    })?;
                }
                managed_shims.insert(shim_name);
            }
        }
    }

    if let Ok(entries) = fs::read_dir(&shims_dir) {
        for entry in entries {
            let entry = match entry {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|value| value.to_str()) {
                Some(value) => value.to_string(),
                None => continue,
            };
            let managed_php = if let Some(digits) = name.strip_prefix("php").and_then(|value| value.strip_suffix(".cmd")) {
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            } else {
                false
            };
            let managed_mysql = if let Some(digits) = name.strip_prefix("mysql").and_then(|value| value.strip_suffix(".cmd")) {
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            } else {
                false
            };
            let managed_mariadb = if let Some(digits) = name.strip_prefix("mariadb").and_then(|value| value.strip_suffix(".cmd")) {
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            } else {
                false
            };
            if (name == "php.cmd"
                || managed_php
                || name == "mysql.cmd"
                || name == "mysqladmin.cmd"
                || managed_mysql
                || name == "mariadb.cmd"
                || managed_mariadb
                || name == "composer.cmd"
                || name == "nginx.cmd")
                && !managed_shims.contains(&name)
            {
                let _ = fs::remove_file(path);
            }
        }
    }

    let legacy_shims_dir = bin_root.join("shims");
    if legacy_shims_dir.exists() {
        if let Ok(entries) = fs::read_dir(&legacy_shims_dir) {
            for entry in entries {
                let entry = match entry {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let name = match path.file_name().and_then(|value| value.to_str()) {
                    Some(value) => value.to_string(),
                    None => continue,
                };
                let managed_legacy = matches!(
                    name.as_str(),
                    "php.cmd"
                        | "nginx.cmd"
                        | "composer.cmd"
                        | "mysql.cmd"
                        | "mysqladmin.cmd"
                        | "mariadb.cmd"
                ) || (name.starts_with("php") && name.ends_with(".cmd"))
                    || (name.starts_with("mysql") && name.ends_with(".cmd"))
                    || (name.starts_with("mariadb") && name.ends_with(".cmd"));
                if managed_legacy {
                    let _ = fs::remove_file(path);
                }
            }
        }
        let _ = fs::remove_dir(&legacy_shims_dir);
    }

    Ok(shims_dir)
}

fn desired_runtime_path_entries(php_install_dir: &Path, mariadb_install_dir: &Path) -> Vec<String> {
    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.to_path_buf());

    let _ = mariadb_install_dir;
    let _ = ensure_runtime_shims(&bin_root);
    vec![bin_root.to_string_lossy().to_string()]
}

fn refresh_user_path_with_runtime_currents(php_install_dir: &Path, mariadb_install_dir: &Path) -> Result<(), String> {
    let desired = desired_runtime_path_entries(php_install_dir, mariadb_install_dir);
    if desired.is_empty() {
        return Ok(());
    }
    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.to_path_buf());
    let legacy_nginx_entry = bin_root.join("nginx").join("current").to_string_lossy().to_string();
    let legacy_shims_entry = bin_root.join("shims").to_string_lossy().to_string();
    let legacy_php_current = php_install_dir.join("current").to_string_lossy().to_string();
    let legacy_mariadb_current_bin = mariadb_install_dir.join("current").join("bin").to_string_lossy().to_string();
    let legacy_composer_entry = bin_root.join("composer").to_string_lossy().to_string();
    let legacy_nvm_symlink = nvm_symlink_path().unwrap_or_default();
    let desired_literal = desired
        .iter()
        .map(|path| format!("'{}'", ps_quote(path)))
        .collect::<Vec<_>>()
        .join(",");
    let legacy_literal = format!(
        "'{}','{}','{}','{}','{}','{}'",
        ps_quote(&legacy_nginx_entry),
        ps_quote(&legacy_shims_entry),
        ps_quote(&legacy_php_current),
        ps_quote(&legacy_mariadb_current_bin),
        ps_quote(&legacy_composer_entry),
        ps_quote(&legacy_nvm_symlink)
    );
    let script = format!(
        "$desired = @({desired_literal}); \
         $legacy = @({legacy_literal}); \
         function Normalize([string]$p) {{ \
           if (-not $p) {{ return '' }} \
           try {{ return [System.IO.Path]::GetFullPath($p).TrimEnd('\\').ToLowerInvariant() }} catch {{ return $p.TrimEnd('\\').ToLowerInvariant() }} \
         }} \
         $userPath = [Environment]::GetEnvironmentVariable('Path','User'); \
         if (-not $userPath) {{ $userPath = '' }}; \
         $parts = $userPath -split ';' | Where-Object {{ $_ -and $_.Trim() -ne '' }}; \
         $desiredNorm = @{{}}; foreach ($d in $desired) {{ $desiredNorm[(Normalize $d)] = $true }}; \
         $legacyNorm = @{{}}; foreach ($l in $legacy) {{ $legacyNorm[(Normalize $l)] = $true }}; \
         $seen = @{{}}; $filtered = New-Object System.Collections.Generic.List[string]; \
         foreach ($p in $parts) {{ \
           $trimmed = $p.Trim(); \
           $norm = Normalize $trimmed; \
           if ($desiredNorm.ContainsKey($norm)) {{ continue }}; \
           if ($legacyNorm.ContainsKey($norm)) {{ continue }}; \
           if (-not $seen.ContainsKey($norm)) {{ $seen[$norm] = $true; [void]$filtered.Add($trimmed) }} \
         }}; \
         $final = @($desired + $filtered) -join ';'; \
         [Environment]::SetEnvironmentVariable('Path', $final, 'User'); \
         'ok'"
    );
    let _ = run_powershell(&script)?;
    Ok(())
}

fn normalize_release_url(candidate: &str) -> String {
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        return candidate.to_string();
    }
    if candidate.starts_with('/') {
        return format!("https://windows.php.net{candidate}");
    }
    format!("https://windows.php.net/downloads/releases/{candidate}")
}

fn version_line(version: &str) -> Option<String> {
    let mut split = version.split('.');
    let major = split.next()?;
    let minor = split.next()?;
    if major.chars().all(|c| c.is_ascii_digit()) && minor.chars().all(|c| c.is_ascii_digit()) {
        Some(format!("{major}.{minor}"))
    } else {
        None
    }
}

fn fetch_php_releases_json_with_cache(cache_path: &PathBuf) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("failed to read clock: {e}"))?
        .as_secs();

    let mut cached: Option<PhpReleaseCache> = None;
    if let Ok(raw) = fs::read_to_string(cache_path) {
        if let Ok(parsed) = serde_json::from_str::<PhpReleaseCache>(&raw) {
            cached = Some(parsed);
        }
    }

    if let Some(cache) = &cached {
        if now.saturating_sub(cache.fetched_at_unix) <= RUNTIME_RELEASES_CACHE_SECONDS {
            return Ok(cache.raw_json.clone());
        }
    }

    let script = format!(
        "$ProgressPreference='SilentlyContinue'; (Invoke-WebRequest -UseBasicParsing -TimeoutSec 12 '{}').Content",
        ps_quote(PHP_RELEASES_URL)
    );
    match run_powershell(&script) {
        Ok(raw_json) => {
            let payload = PhpReleaseCache {
                fetched_at_unix: now,
                raw_json: raw_json.clone(),
            };
            if let Ok(content) = serde_json::to_string_pretty(&payload) {
                let _ = fs::write(cache_path, content);
            }
            Ok(raw_json)
        }
        Err(fetch_error) => {
            if let Some(cache) = cached {
                Ok(cache.raw_json)
            } else {
                Err(format!(
                    "failed to fetch PHP releases and no cache available: {fetch_error}"
                ))
            }
        }
    }
}

fn latest_builds_with_fallback(cache_path: &PathBuf) -> HashMap<String, PhpReleaseBuild> {
    let raw = match fetch_php_releases_json_with_cache(cache_path) {
        Ok(value) => value,
        Err(_) => return HashMap::new(),
    };
    latest_builds_by_line(&raw).unwrap_or_default()
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    if is_version_gt(a, b) {
        std::cmp::Ordering::Greater
    } else if is_version_gt(b, a) {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Equal
    }
}

fn looks_like_semver(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 2 || parts.len() > 4 {
        return false;
    }
    parts
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn extract_versions_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split_whitespace() {
        let cleaned = token
            .trim_matches(|c: char| !(c.is_ascii_digit() || c == '.'))
            .to_string();
        if looks_like_semver(&cleaned) {
            out.push(cleaned);
        }
    }
    out.sort_by(|a, b| compare_versions(b, a));
    out.dedup();
    out
}

fn major_from_version(version: &str) -> Option<String> {
    version.split('.').next().map(|s| s.to_string())
}

fn latest_by_major(versions: &[String]) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for version in versions {
        let Some(major) = major_from_version(version) else {
            continue;
        };
        match out.get(&major) {
            None => {
                out.insert(major, version.clone());
            }
            Some(current) => {
                if compare_versions(version, current) == std::cmp::Ordering::Greater {
                    out.insert(major, version.clone());
                }
            }
        }
    }
    out
}

fn preferred_node_majors() -> Vec<String> {
    vec![
        "25".to_string(),
        "22".to_string(),
        "20".to_string(),
        "18".to_string(),
        "16".to_string(),
    ]
}

fn build_node_catalog() -> NodeCatalogResponse {
    let available_output = match run_nvm_command(&["list", "available"]) {
        Ok(output) => output,
        Err(error) => {
            return NodeCatalogResponse {
                nvm_available: false,
                error: Some(format!("nvm is not available: {error}")),
                current_version: None,
                installed_versions: vec![],
                runtimes: vec![],
            }
        }
    };
    let installed_output = run_nvm_command(&["list"]).unwrap_or_default();
    let current_output = run_nvm_command(&["current"]).unwrap_or_default();
    let available_versions = extract_versions_from_text(&available_output);
    let installed_versions = extract_versions_from_text(&installed_output);
    let current_version = extract_versions_from_text(&current_output).into_iter().next();
    let available_latest = latest_by_major(&available_versions);
    let installed_latest = latest_by_major(&installed_versions);

    let mut majors = preferred_node_majors();
    for major in available_latest.keys() {
        if !majors.contains(major) {
            majors.push(major.clone());
        }
    }
    majors.sort_by(|a, b| compare_versions(b, a));
    majors.dedup();

    let runtimes = majors
        .into_iter()
        .map(|major| NodeLineRuntime {
            line: major.clone(),
            latest_version: available_latest.get(&major).cloned(),
            installed_version: installed_latest.get(&major).cloned(),
            is_current: current_version
                .as_ref()
                .and_then(|version| major_from_version(version))
                .map(|value| value == major)
                .unwrap_or(false),
        })
        .collect();

    NodeCatalogResponse {
        nvm_available: true,
        error: None,
        current_version,
        installed_versions,
        runtimes,
    }
}

fn download_with_progress<F: FnMut(f64)>(
    url: &str,
    destination: &Path,
    mut progress: F,
) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("failed to create http client: {e}"))?;
    let mut response = client
        .get(url)
        .header("User-Agent", "Envloom/0.1.0")
        .header("Accept", "*/*")
        .send()
        .map_err(|e| format!("failed to download {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download returned error for {url}: {e}"))?;

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create destination dir: {e}"))?;
    }
    let mut file = File::create(destination).map_err(|e| format!("failed to create file: {e}"))?;
    let total = response.content_length();
    let mut downloaded = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    progress(0.0);
    loop {
        let n = response
            .read(&mut buffer)
            .map_err(|e| format!("failed while downloading: {e}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buffer[..n])
            .map_err(|e| format!("failed writing download file: {e}"))?;
        downloaded = downloaded.saturating_add(n as u64);
        if let Some(total_bytes) = total {
            if total_bytes > 0 {
                let pct = (downloaded as f64 * 100.0) / total_bytes as f64;
                progress(pct.min(100.0));
            }
        }
    }
    progress(100.0);
    Ok(())
}

fn shared_downloads_dir(base: &Path) -> PathBuf {
    base.join("_downloads")
}

fn ensure_zip_signature(path: &Path) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| format!("failed to open downloaded file: {e}"))?;
    let mut sig = [0u8; 2];
    file.read_exact(&mut sig)
        .map_err(|e| format!("failed reading downloaded file signature: {e}"))?;
    if sig != [b'P', b'K'] {
        let preview = fs::read_to_string(path)
            .ok()
            .map(|s| s.chars().take(220).collect::<String>())
            .unwrap_or_else(|| "binary/non-text response".to_string());
        return Err(format!(
            "downloaded file is not a valid zip (missing PK signature). Response preview: {preview}"
        ));
    }
    Ok(())
}

fn normalize_sha256(raw: &str) -> Option<String> {
    let value = raw.trim().to_lowercase();
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(value)
}

fn verify_file_sha256(path: &Path, expected_sha256: &str) -> Result<(), String> {
    let expected = normalize_sha256(expected_sha256)
        .ok_or_else(|| format!("invalid expected sha256 format: {expected_sha256}"))?;
    let mut file = File::open(path).map_err(|e| format!("failed to open file for sha256: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("failed reading file for sha256: {e}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err(format!(
            "sha256 mismatch. expected: {expected}, actual: {actual}"
        ));
    }
    Ok(())
}

fn get_json_with_user_agent(url: &str, user_agent: &str) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("failed to create http client: {e}"))?;
    client
        .get(url)
        .header("User-Agent", user_agent)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("request returned error status: {e}"))?
        .text()
        .map_err(|e| format!("failed to read response body: {e}"))
}

fn latest_nginx_release_asset() -> Result<(String, String), String> {
    let raw = get_json_with_user_agent(NGINX_RELEASES_URL, "Envloom/0.1.0")?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse nginx releases json: {e}"))?;
    let releases = value
        .as_array()
        .ok_or_else(|| "nginx releases json is not an array".to_string())?;
    let first = releases
        .first()
        .ok_or_else(|| "nginx releases list is empty".to_string())?;
    let assets = first
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| "nginx latest release has no assets array".to_string())?;

    for asset in assets {
        let Some(name) = asset.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(url) = asset.get("browser_download_url").and_then(Value::as_str) else {
            continue;
        };
        let lower = name.to_lowercase();
        if lower.starts_with("nginx-") && lower.ends_with(".zip") {
            let version = name
                .trim_start_matches("nginx-")
                .trim_end_matches(".zip")
                .to_string();
            if looks_like_semver(&version) {
                return Ok((version, url.to_string()));
            }
        }
    }

    Err("could not find nginx-version.zip in latest release assets".to_string())
}

fn flatten_nested_dir(line_dir: &Path, nested_name: &str) -> Result<(), String> {
    let nested = line_dir.join(nested_name);
    if !nested.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(&nested).map_err(|e| format!("failed to read nested nginx dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed reading nested nginx entry: {e}"))?;
        let src = entry.path();
        let dst = line_dir.join(entry.file_name());
        if dst.exists() {
            if dst.is_dir() {
                fs::remove_dir_all(&dst).map_err(|e| format!("failed to replace nginx dir: {e}"))?;
            } else {
                fs::remove_file(&dst).map_err(|e| format!("failed to replace nginx file: {e}"))?;
            }
        }
        fs::rename(&src, &dst).map_err(|e| format!("failed to move nginx extracted file: {e}"))?;
    }
    fs::remove_dir_all(&nested).map_err(|e| format!("failed to cleanup nested nginx dir: {e}"))?;
    Ok(())
}

fn install_latest_nginx_with_progress<F: FnMut(f64)>(bin_root: &Path, mut progress: F) -> Result<String, String> {
    let (version, url) = latest_nginx_release_asset()?;
    let nginx_root = bin_root.join("nginx");
    let line_dir = nginx_root.join(&version);
    if line_dir.join("nginx.exe").exists() {
        progress(100.0);
        return Ok(version);
    }

    fs::create_dir_all(&nginx_root).map_err(|e| format!("failed to create nginx dir: {e}"))?;
    if line_dir.exists() {
        fs::remove_dir_all(&line_dir).map_err(|e| format!("failed to clear nginx version dir: {e}"))?;
    }
    fs::create_dir_all(&line_dir).map_err(|e| format!("failed to create nginx version dir: {e}"))?;
    let downloads = shared_downloads_dir(bin_root);
    fs::create_dir_all(&downloads).map_err(|e| format!("failed to create nginx downloads dir: {e}"))?;
    let zip_path = downloads.join(format!("nginx-{version}.zip"));
    if zip_path.exists() {
        let _ = fs::remove_file(&zip_path);
    }

    download_with_progress(&url, &zip_path, &mut progress)?;
    ensure_zip_signature(&zip_path)?;
    let extract_result = (|| -> Result<(), String> {
        extract_zip_file(&zip_path, &line_dir)?;
        flatten_nested_dir(&line_dir, &format!("nginx-{version}"))?;
        Ok(())
    })();
    let _ = fs::remove_file(&zip_path);
    extract_result?;
    let _ = set_nginx_current_link(&nginx_root, &version);
    Ok(version)
}

fn select_latest_mariadb_asset(raw: &str) -> Result<(String, String, Option<String>), String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|e| format!("failed to parse mariadb latest json: {e}"))?;
    let releases = value
        .get("releases")
        .and_then(Value::as_object)
        .ok_or_else(|| "mariadb latest endpoint returned no releases map".to_string())?;

    let mut ordered: Vec<&Value> = releases.values().collect();
    ordered.sort_by(|a, b| {
        let av = a
            .get("release_id")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0");
        let bv = b
            .get("release_id")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0");
        compare_versions(bv, av)
    });

    for release in ordered {
        let release_id = release
            .get("release_id")
            .and_then(Value::as_str)
            .unwrap_or("latest")
            .to_string();
        let Some(files) = release.get("files").and_then(Value::as_array) else {
            continue;
        };
        for file in files {
            let Some(url) = file
                .get("file_download_url")
                .and_then(Value::as_str)
                .or_else(|| file.get("download_url").and_then(Value::as_str))
            else {
                continue;
            };
            let name = file
                .get("file_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let package_type = file
                .get("package_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let cpu = file
                .get("cpu")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            let os = file
                .get("os")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();

            let is_zip = name.ends_with(".zip") || package_type.contains("zip");
            let is_windows = name.contains("win") || os.contains("windows");
            let is_x64 =
                name.contains("winx64") || name.contains("x86_64") || cpu.contains("x86_64") || cpu.contains("amd64");
            let is_debug_or_non_runtime = name.contains("debug")
                || name.contains("symbol")
                || name.contains("pdb")
                || name.contains("source")
                || name.contains("test");
            if is_zip && is_windows && is_x64 && !is_debug_or_non_runtime {
                let sha256 = file
                    .get("sha256")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| file.get("checksum").and_then(Value::as_str).map(str::to_string))
                    .or_else(|| file.get("file_checksum").and_then(Value::as_str).map(str::to_string))
                    .and_then(|value| normalize_sha256(&value));
                return Ok((release_id, url.to_string(), sha256));
            }
        }
    }

    Err("could not find a MariaDB Windows x64 zip asset in latest release".to_string())
}

fn flatten_single_nested_dir(line_dir: &Path) -> Result<(), String> {
    let entries = fs::read_dir(line_dir).map_err(|e| format!("failed to read extracted dir: {e}"))?;
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read extracted entry: {e}"))?;
        if entry.path().is_dir() {
            dirs.push(entry.path());
        } else {
            files.push(entry.path());
        }
    }
    if dirs.len() != 1 || !files.is_empty() {
        return Ok(());
    }
    let nested = &dirs[0];
    let nested_entries = fs::read_dir(nested).map_err(|e| format!("failed to read nested dir: {e}"))?;
    for entry in nested_entries {
        let entry = entry.map_err(|e| format!("failed to read nested entry: {e}"))?;
        let src = entry.path();
        let dst = line_dir.join(entry.file_name());
        if dst.exists() {
            if dst.is_dir() {
                fs::remove_dir_all(&dst).map_err(|e| format!("failed to replace nested dir: {e}"))?;
            } else {
                fs::remove_file(&dst).map_err(|e| format!("failed to replace nested file: {e}"))?;
            }
        }
        fs::rename(&src, &dst).map_err(|e| format!("failed moving nested extracted entry: {e}"))?;
    }
    fs::remove_dir_all(nested).map_err(|e| format!("failed cleaning nested dir: {e}"))?;
    Ok(())
}

fn fetch_mariadb_builds_with_cache(cache_path: &PathBuf) -> Result<HashMap<String, MariaDbReleaseBuild>, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("failed to read clock: {e}"))?
        .as_secs();

    if let Ok(raw) = fs::read_to_string(cache_path) {
        if let Ok(cache) = serde_json::from_str::<MariaDbReleasesCache>(&raw) {
            if now.saturating_sub(cache.fetched_at_unix) <= RUNTIME_RELEASES_CACHE_SECONDS {
                let mut map = HashMap::new();
                for build in cache.builds {
                    map.insert(build.line.clone(), build);
                }
                return Ok(map);
            }
        }
    }

    let majors_raw = get_json_with_user_agent(MARIADB_RELEASES_URL, "Envloom/0.1.0")?;
    let value: Value =
        serde_json::from_str(&majors_raw).map_err(|e| format!("failed to parse mariadb majors json: {e}"))?;
    let majors_arr = value
        .get("major_releases")
        .and_then(Value::as_array)
        .ok_or_else(|| "mariadb api did not return major_releases array".to_string())?;
    let mut majors: Vec<String> = majors_arr
        .iter()
        .filter_map(|entry| {
            let release_id = entry.get("release_id").and_then(Value::as_str)?;
            let status = entry
                .get("release_status")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            if status.contains("stable") {
                Some(release_id.to_string())
            } else {
                None
            }
        })
        .collect();
    if majors.is_empty() {
        majors = majors_arr
            .iter()
            .filter_map(|entry| entry.get("release_id").and_then(Value::as_str).map(str::to_string))
            .collect();
    }
    majors.sort_by(|a, b| compare_versions(b, a));
    majors.dedup();

    let mut builds = Vec::new();
    for major in majors {
        let latest_url = format!("{MARIADB_RELEASES_URL}{major}/latest/");
        let latest_raw = match get_json_with_user_agent(&latest_url, "Envloom/0.1.0") {
            Ok(value) => value,
            Err(_) => continue,
        };
        let (version, url, sha256) = match select_latest_mariadb_asset(&latest_raw) {
            Ok(value) => value,
            Err(_) => continue,
        };
        builds.push(MariaDbReleaseBuild {
            line: major,
            version,
            url,
            sha256,
        });
    }

    let payload = MariaDbReleasesCache {
        fetched_at_unix: now,
        builds: builds.clone(),
    };
    if let Ok(raw) = serde_json::to_string_pretty(&payload) {
        let _ = fs::write(cache_path, raw);
    }

    let mut map = HashMap::new();
    for build in builds {
        map.insert(build.line.clone(), build);
    }
    Ok(map)
}

fn latest_mariadb_builds_with_fallback(cache_path: &PathBuf) -> HashMap<String, MariaDbReleaseBuild> {
    fetch_mariadb_builds_with_cache(cache_path).unwrap_or_default()
}

fn install_mariadb_line_build_with_progress<F: FnMut(f64)>(
    install_dir: &Path,
    line: &str,
    build: &MariaDbReleaseBuild,
    mut progress: F,
) -> Result<(), String> {
    let line_dir = install_dir.join(line);
    if line_dir.exists() {
        fs::remove_dir_all(&line_dir).map_err(|e| format!("failed to clear mariadb line dir: {e}"))?;
    }
    fs::create_dir_all(&line_dir).map_err(|e| format!("failed to create mariadb line dir: {e}"))?;

    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.to_path_buf());
    let downloads = shared_downloads_dir(&bin_root);
    fs::create_dir_all(&downloads).map_err(|e| format!("failed to create mariadb downloads dir: {e}"))?;
    let zip_path = downloads.join(format!("mariadb-{}-winx64.zip", build.version));
    if zip_path.exists() {
        let _ = fs::remove_file(&zip_path);
    }
    download_with_progress(&build.url, &zip_path, &mut progress)?;
    ensure_zip_signature(&zip_path)?;
    if let Some(expected_sha256) = build.sha256.as_deref() {
        verify_file_sha256(&zip_path, expected_sha256)?;
    }
    let extract_result = (|| -> Result<(), String> {
        extract_zip_file(&zip_path, &line_dir)?;
        flatten_single_nested_dir(&line_dir)?;
        Ok(())
    })();
    let _ = fs::remove_file(&zip_path);
    extract_result?;
    Ok(())
}

fn install_php_line_build_with_progress<F: FnMut(f64)>(
    install_dir: &Path,
    line: &str,
    build: &PhpReleaseBuild,
    mut progress: F,
) -> Result<(), String> {
    let line_dir = install_dir.join(line);
    if line_dir.exists() {
        fs::remove_dir_all(&line_dir).map_err(|e| format!("failed to clear php line directory: {e}"))?;
    }
    fs::create_dir_all(&line_dir).map_err(|e| format!("failed to create php line directory: {e}"))?;

    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.to_path_buf());
    let downloads_dir = shared_downloads_dir(&bin_root);
    fs::create_dir_all(&downloads_dir).map_err(|e| format!("failed to create downloads dir: {e}"))?;
    let zip_path = downloads_dir.join(format!("php-{}-ts-x64.zip", build.version));
    if zip_path.exists() {
        let _ = fs::remove_file(&zip_path);
    }

    download_with_progress(&build.url, &zip_path, &mut progress)?;
    ensure_zip_signature(&zip_path)?;
    if let Some(expected_sha256) = build.sha256.as_deref() {
        verify_file_sha256(&zip_path, expected_sha256)?;
    }

    let extract_result = extract_zip_file(&zip_path, &line_dir);
    let _ = fs::remove_file(&zip_path);
    extract_result?;
    Ok(())
}

fn latest_builds_by_line(raw_json: &str) -> Result<HashMap<String, PhpReleaseBuild>, String> {
    let value: Value =
        serde_json::from_str(raw_json).map_err(|e| format!("failed to parse releases.json: {e}"))?;
    let mut latest: HashMap<String, PhpReleaseBuild> = HashMap::new();

    let root = value
        .as_object()
        .ok_or_else(|| "releases.json root is not an object".to_string())?;

    for (line, line_value) in root {
        if version_line(&format!("{line}.0")).is_none() {
            continue;
        }
        let Some(line_obj) = line_value.as_object() else {
            continue;
        };
        let Some(version) = line_obj.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()) else {
            continue;
        };

        let mut zip_path: Option<String> = None;
        let mut zip_sha256: Option<String> = None;
        for (k, v) in line_obj {
            let key = k.to_lowercase();
            if !key.starts_with("ts-") || !key.ends_with("-x64") {
                continue;
            }
            if let Some(zip_obj) = v
                .as_object()
                .and_then(|o| o.get("zip"))
                .and_then(|z| z.as_object())
            {
                if let Some(path) = zip_obj.get("path").and_then(|p| p.as_str()) {
                    zip_path = Some(path.to_string());
                    zip_sha256 = zip_obj
                        .get("sha256")
                        .and_then(|s| s.as_str())
                        .and_then(normalize_sha256);
                    break;
                }
            }
        }
        if let Some(path) = zip_path {
            latest.insert(
                line.clone(),
                PhpReleaseBuild {
                    line: line.clone(),
                    version,
                    url: normalize_release_url(&path),
                    sha256: zip_sha256,
                },
            );
        }
    }
    Ok(latest)
}

fn set_php_current_link(install_dir: &PathBuf, line: &str) -> Result<(), String> {
    let target = install_dir.join(line);
    if !target.exists() {
        return Err(format!("cannot set current link, target does not exist: {}", target.display()));
    }
    let link_path = install_dir.join("current");
    let script = format!(
        "if (Test-Path -LiteralPath '{link}') {{ Remove-Item -LiteralPath '{link}' -Force -Recurse }}; New-Item -ItemType Junction -Path '{link}' -Target '{target}' | Out-Null",
        link = ps_quote(&link_path.to_string_lossy()),
        target = ps_quote(&target.to_string_lossy()),
    );
    run_powershell(&script)?;
    Ok(())
}

fn set_mariadb_current_link(install_dir: &PathBuf, line: &str) -> Result<(), String> {
    let target = install_dir.join(line);
    if !target.exists() {
        return Err(format!(
            "cannot set current link, target does not exist: {}",
            target.display()
        ));
    }
    let link_path = install_dir.join("current");
    let script = format!(
        "if (Test-Path -LiteralPath '{link}') {{ Remove-Item -LiteralPath '{link}' -Force -Recurse }}; New-Item -ItemType Junction -Path '{link}' -Target '{target}' | Out-Null",
        link = ps_quote(&link_path.to_string_lossy()),
        target = ps_quote(&target.to_string_lossy()),
    );
    run_powershell(&script)?;
    Ok(())
}

fn set_nginx_current_link(nginx_root: &PathBuf, version: &str) -> Result<(), String> {
    let target = nginx_root.join(version);
    if !target.exists() {
        return Err(format!(
            "cannot set nginx current link, target does not exist: {}",
            target.display()
        ));
    }
    let link_path = nginx_root.join("current");
    let script = format!(
        "if (Test-Path -LiteralPath '{link}') {{ Remove-Item -LiteralPath '{link}' -Force -Recurse }}; New-Item -ItemType Junction -Path '{link}' -Target '{target}' | Out-Null",
        link = ps_quote(&link_path.to_string_lossy()),
        target = ps_quote(&target.to_string_lossy()),
    );
    run_powershell(&script)?;
    Ok(())
}

fn ensure_nginx_current_link(nginx_root: &PathBuf) -> Result<(), String> {
    let current = nginx_root.join("current").join("nginx.exe");
    if current.exists() {
        return Ok(());
    }
    if !nginx_root.exists() {
        return Ok(());
    }
    let mut versions: Vec<String> = Vec::new();
    let entries = fs::read_dir(nginx_root).map_err(|e| format!("failed to read nginx root: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read nginx entry: {e}"))?;
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "current" || name.starts_with('_') {
            continue;
        }
        if entry.path().join("nginx.exe").exists() && looks_like_semver(&name) {
            versions.push(name);
        }
    }
    if versions.is_empty() {
        return Ok(());
    }
    versions.sort_by(|a, b| compare_versions(b, a));
    set_nginx_current_link(nginx_root, &versions[0])
}

fn detect_php_version_from_binary(line_dir: &PathBuf) -> Option<String> {
    let php_exe = line_dir.join("php.exe");
    if !php_exe.exists() {
        return None;
    }
    let output = Command::new(&php_exe)
        .args(["-r", "echo PHP_VERSION;"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn sync_local_php_installations(install_dir: &PathBuf, config: &mut PhpConfig) -> Result<(), String> {
    if !install_dir.exists() {
        fs::create_dir_all(install_dir).map_err(|e| format!("failed to create php install dir: {e}"))?;
    }
    let mut discovered_installed: HashMap<String, Vec<String>> = HashMap::new();
    let mut discovered_active: HashMap<String, String> = HashMap::new();
    let entries = fs::read_dir(install_dir).map_err(|e| format!("failed to read php install dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read directory entry: {e}"))?;
        if !entry.path().is_dir() {
            continue;
        }
        let line = entry.file_name().to_string_lossy().to_string();
        if version_line(&format!("{line}.0")).is_none() {
            continue;
        }
        let line_dir = entry.path();
        let php_exe = line_dir.join("php.exe");
        let php_cgi_exe = line_dir.join("php-cgi.exe");
        if !php_exe.exists() || !php_cgi_exe.exists() {
            let _ = fs::remove_dir_all(&line_dir);
            continue;
        }
        let fallback = config
            .active
            .get(&line)
            .cloned()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| line.clone());
        let full_version = detect_php_version_from_binary(&line_dir).unwrap_or(fallback);
        discovered_installed.insert(line.clone(), vec![full_version.clone()]);
        discovered_active.insert(line, full_version);
    }
    config.installed = discovered_installed;
    config.active.retain(|line, _| config.installed.contains_key(line));
    for (line, version) in discovered_active {
        config.active.insert(line, version);
    }
    if let Some(current_line) = config.current_line.clone() {
        if !config.installed.contains_key(&current_line) {
            config.current_line = None;
        }
    }
    Ok(())
}

fn detect_mariadb_version_from_binary(line_dir: &PathBuf) -> Option<String> {
    let mariadbd = line_dir.join("bin").join("mariadbd.exe");
    if !mariadbd.exists() {
        return None;
    }
    let output = Command::new(&mariadbd).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|c: char| !(c.is_ascii_digit() || c == '.'));
        if looks_like_semver(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn is_process_running(process_name: &str) -> bool {
    let script = format!(
        "$procs = Get-Process -Name '{name}' -ErrorAction SilentlyContinue; \
         if ($procs) {{ '1' }} else {{ '0' }}",
        name = process_name.replace(".exe", "")
    );
    match run_powershell(&script) {
        Ok(output) => output.trim() == "1",
        Err(_) => false,
    }
}

fn stop_processes_by_exact_path(executable_path: &Path) -> Result<(), String> {
    let script = format!(
        "$target='{target}'; \
         Get-Process -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath -eq $target }} | \
         Stop-Process -Force -ErrorAction SilentlyContinue; \
         'ok'",
        target = ps_quote(&executable_path.to_string_lossy())
    );
    let _ = run_powershell(&script)?;
    Ok(())
}

fn is_mariadb_listening_in_root(_install_dir: &PathBuf, port: u16) -> bool {
    is_local_tcp_port_open(port)
}

fn detect_nginx_version_from_binary(nginx_root: &PathBuf) -> Option<String> {
    let _ = ensure_nginx_current_link(nginx_root);
    let nginx_exe = nginx_root.join("current").join("nginx.exe");
    if !nginx_exe.exists() {
        return None;
    }
    let output = Command::new(&nginx_exe).arg("-v").output().ok()?;
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for token in text.split_whitespace() {
        if let Some(value) = token.strip_prefix("nginx/") {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn start_nginx_if_needed(nginx_root: &PathBuf) -> Result<(), String> {
    fn tail_text(content: &str, max_lines: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(max_lines);
        lines[start..].join("\n")
    }

    ensure_nginx_current_link(nginx_root)?;
    let nginx_exe = nginx_root.join("current").join("nginx.exe");
    if !nginx_exe.exists() {
        return Ok(());
    }
    if is_process_running("nginx.exe") {
        return Ok(());
    }
    let current_dir = nginx_root.join("current");

    let test_output = Command::new(&nginx_exe)
        .args(["-t", "-p", &current_dir.to_string_lossy()])
        .current_dir(&current_dir)
        .output()
        .map_err(|e| format!("failed to execute nginx -t: {e}"))?;
    if !test_output.status.success() {
        let stderr = String::from_utf8_lossy(&test_output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&test_output.stdout).trim().to_string();
        return Err(format!("nginx config test failed. stdout: {stdout}. stderr: {stderr}"));
    }

    let script = format!(
        "Start-Process -WindowStyle Hidden -FilePath '{exe}' -WorkingDirectory '{cwd}' -ArgumentList '-p','{cwd}' | Out-Null",
        exe = ps_quote(&nginx_exe.to_string_lossy()),
        cwd = ps_quote(&current_dir.to_string_lossy())
    );
    run_powershell(&script)?;
    let mut ok = false;
    for _ in 0..12 {
        if is_process_running("nginx.exe") {
            ok = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    if !ok {
        let bin_root = nginx_root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| nginx_root.to_path_buf());
        let err_log = resolve_logs_dir_from_bin_root(&bin_root).join("nginx").join("error.log");
        let log_tail = fs::read_to_string(&err_log)
            .ok()
            .map(|raw| tail_text(&raw, 80))
            .unwrap_or_else(|| format!("no nginx error log found at {}", err_log.display()));
        return Err(format!("nginx process exits immediately after start. error log tail:\n{log_tail}"));
    }
    Ok(())
}

fn stop_nginx_if_running(nginx_root: &PathBuf) -> Result<(), String> {
    ensure_nginx_current_link(nginx_root)?;
    let current_dir = nginx_root.join("current");
    let nginx_exe = current_dir.join("nginx.exe");
    if nginx_exe.exists() {
        let _ = Command::new(&nginx_exe)
            .args(["-s", "stop", "-p", &current_dir.to_string_lossy()])
            .current_dir(&current_dir)
            .output();
    }
    if is_process_running("nginx.exe") {
        let script = format!(
            "$root='{root}'; \
             Get-Process -Name 'nginx' -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath -like ($root + '*') }} | \
             ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}",
            root = ps_quote(&nginx_root.to_string_lossy())
        );
        let _ = run_powershell(&script);
    }
    Ok(())
}

fn reload_nginx_if_running(nginx_root: &PathBuf) -> Result<(), String> {
    ensure_nginx_current_link(nginx_root)?;
    let current_dir = nginx_root.join("current");
    let nginx_exe = current_dir.join("nginx.exe");
    if !nginx_exe.exists() {
        return Ok(());
    }
    if !is_process_running("nginx.exe") {
        return start_nginx_if_needed(nginx_root);
    }
    let output = Command::new(&nginx_exe)
        .args(["-s", "reload", "-p", &current_dir.to_string_lossy()])
        .current_dir(&current_dir)
        .output()
        .map_err(|e| format!("failed to execute nginx reload: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(format!("nginx reload failed. stdout: {stdout}. stderr: {stderr}"));
    }
    Ok(())
}

fn to_nginx_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn ensure_local_ca(sites_dir: &Path) -> Result<(rcgen::Certificate, KeyPair, PathBuf), String> {
    let ca_dir = sites_dir.join("ca");
    fs::create_dir_all(&ca_dir).map_err(|e| format!("failed to create ca dir: {e}"))?;
    let ca_crt_path = ca_dir.join("ca.crt");
    let ca_key_path = ca_dir.join("ca.key");

    let (ca_cert, ca_key) = if ca_crt_path.exists() && ca_key_path.exists() {
        let ca_cert_pem = fs::read_to_string(&ca_crt_path)
            .map_err(|e| format!("failed to read existing ca.crt: {e}"))?;
        let ca_key_pem = fs::read_to_string(&ca_key_path)
            .map_err(|e| format!("failed to read existing ca.key: {e}"))?;
        let ca_key = KeyPair::from_pem(&ca_key_pem)
            .map_err(|e| format!("failed to parse existing ca.key: {e}"))?;
        let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
            .map_err(|e| format!("failed to parse existing ca.crt: {e}"))?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| format!("failed to load existing CA certificate: {e}"))?;
        (ca_cert, ca_key)
    } else {
        let mut ca_params =
            CertificateParams::new(vec![]).map_err(|e| format!("failed to init CA params: {e}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Envloom Local CA");
        dn.push(DnType::OrganizationName, "Envloom");
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().map_err(|e| format!("failed to generate CA key: {e}"))?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| format!("failed to generate CA certificate: {e}"))?;
        fs::write(&ca_crt_path, ca_cert.pem())
            .map_err(|e| format!("failed to write ca.crt: {e}"))?;
        fs::write(&ca_key_path, ca_key.serialize_pem())
            .map_err(|e| format!("failed to write ca.key: {e}"))?;
        (ca_cert, ca_key)
    };

    let _ = trust_certificate_for_current_user(&ca_crt_path);
    Ok((ca_cert, ca_key, ca_crt_path))
}

fn ensure_site_ssl_cert(sites_dir: &Path, domain: &str) -> Result<(PathBuf, PathBuf), String> {
    let certs_dir = sites_dir.join("certs");
    fs::create_dir_all(&certs_dir).map_err(|e| format!("failed to create certs dir: {e}"))?;
    let crt_path = certs_dir.join(format!("{domain}.crt"));
    let key_path = certs_dir.join(format!("{domain}.key"));
    if crt_path.exists() {
        let _ = fs::remove_file(&crt_path);
    }
    if key_path.exists() {
        let _ = fs::remove_file(&key_path);
    }

    let mut sans = vec![domain.to_string(), format!("www.{domain}")];
    if let Some((_, tld)) = domain.split_once('.') {
        sans.push(format!("*.{tld}"));
    }
    let (ca_cert, ca_key, _ca_crt_path) = ensure_local_ca(sites_dir)?;
    let mut cert_params =
        CertificateParams::new(sans).map_err(|e| format!("failed to init site cert params: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain.to_string());
    cert_params.distinguished_name = dn;
    let cert_key = KeyPair::generate().map_err(|e| format!("failed to generate site key: {e}"))?;
    let cert = cert_params
        .signed_by(&cert_key, &ca_cert, &ca_key)
        .map_err(|e| format!("failed to sign site certificate: {e}"))?;
    let cert_pem = cert.pem();
    let key_pem = cert_key.serialize_pem();
    fs::write(&crt_path, cert_pem).map_err(|e| format!("failed to write certificate: {e}"))?;
    fs::write(&key_path, key_pem).map_err(|e| format!("failed to write private key: {e}"))?;
    Ok((crt_path, key_path))
}

fn trust_certificate_for_current_user(cert_path: &Path) -> Result<(), String> {
    let output = Command::new("certutil")
        .args([
            "-user",
            "-addstore",
            "Root",
            &cert_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("failed to execute certutil: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(format!("failed to trust certificate. stdout: {stdout}. stderr: {stderr}"));
    }
    Ok(())
}

fn ensure_nginx_sites_include(nginx_root: &Path, sites_dir: &Path) -> Result<(), String> {
    let conf_dir = nginx_root.join("current").join("conf");
    fs::create_dir_all(sites_dir).map_err(|e| format!("failed to create sites dir: {e}"))?;
    let logs_root = sites_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sites_dir.to_path_buf())
        .join("logs")
        .join("nginx");
    fs::create_dir_all(logs_root.join("sites")).map_err(|e| format!("failed to create nginx logs dir: {e}"))?;
    let nginx_conf = conf_dir.join("nginx.conf");
    let mut content =
        fs::read_to_string(&nginx_conf).map_err(|e| format!("failed to read nginx.conf: {e}"))?;
    let include_target = format!("{}/{}.conf", to_nginx_path(sites_dir), "*");
    let global_error_log = format!("{}/error.log", to_nginx_path(&logs_root));
    let global_access_log = format!("{}/access.log", to_nginx_path(&logs_root));
    let has_include = content.contains(&include_target);
    let has_global_error = content.contains(&global_error_log);
    let has_global_access = content.contains(&global_access_log);
    if has_include && has_global_error && has_global_access {
        return Ok(());
    }
    let Some(http_idx) = content.find("http {") else {
        return Err("nginx.conf does not contain an http block".to_string());
    };
    let mut depth = 0_i32;
    let mut insert_at: Option<usize> = None;
    for (idx, ch) in content[http_idx..].char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                insert_at = Some(http_idx + idx);
                break;
            }
        }
    }
    let Some(pos) = insert_at else {
        return Err("failed to locate end of nginx http block".to_string());
    };
    let mut inserts = String::new();
    if !has_global_error {
        inserts.push_str(&format!("\n    error_log     {global_error_log};\n"));
    }
    if !has_global_access {
        inserts.push_str(&format!("    access_log    {global_access_log};\n"));
    }
    if !has_include {
        inserts.push_str(&format!("    include       {include_target};\n"));
    }
    content.insert_str(pos, &inserts);
    fs::write(&nginx_conf, content).map_err(|e| format!("failed to update nginx.conf: {e}"))?;
    Ok(())
}

fn write_nginx_site_config(
    nginx_root: &Path,
    sites_dir: &Path,
    domain: &str,
    site_path: &Path,
    php_fpm_port: u16,
    ssl_enabled: bool,
) -> Result<(), String> {
    ensure_nginx_sites_include(nginx_root, sites_dir)?;
    let conf_path = sites_dir.join(format!("{domain}.conf"));
    let nginx_logs_root = sites_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sites_dir.to_path_buf())
        .join("logs")
        .join("nginx");
    let site_logs_dir = nginx_logs_root.join("sites");
    fs::create_dir_all(&site_logs_dir).map_err(|e| format!("failed to create nginx site logs dir: {e}"))?;
    let access_log = to_nginx_path(&site_logs_dir.join(format!("{domain}.access.log")));
    let error_log = to_nginx_path(&site_logs_dir.join(format!("{domain}.error.log")));
    let root_path = if site_path.join("public").exists() {
        site_path.join("public")
    } else {
        site_path.to_path_buf()
    };
    let root = root_path.to_string_lossy().replace('\\', "/");
    let mut content = format!(
        "server {{
    listen 80;
    server_name {domain};
    access_log {access_log};
    error_log {error_log};
"
    );
    if ssl_enabled {
        content.push_str("    return 301 https://$host$request_uri;\n}\n\n");
        let (crt_path, key_path) = ensure_site_ssl_cert(sites_dir, domain)?;
        content.push_str(&format!(
            "server {{
    listen 443 ssl;
    server_name {domain};
    access_log {access_log};
    error_log {error_log};
    ssl_certificate {};
    ssl_certificate_key {};
",
            to_nginx_path(&crt_path),
            to_nginx_path(&key_path)
        ));
    } else {
        content.push_str("");
    }
    content.push_str(&format!(
        "    root {root};
    index index.php index.html index.htm;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location ~ \\.php$ {{
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass 127.0.0.1:{php_fpm_port};
    }}
}}
"
    ));
    let current = fs::read_to_string(&conf_path).unwrap_or_default();
    if current != content {
        fs::write(conf_path, content).map_err(|e| format!("failed to write nginx site config: {e}"))?;
    }
    Ok(())
}

fn reconcile_nginx_site_configs(sites_dir: &Path, domains: &[String]) -> Result<(), String> {
    fs::create_dir_all(sites_dir).map_err(|e| format!("failed to create sites dir: {e}"))?;
    let managed: HashSet<String> = domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    if let Ok(entries) = fs::read_dir(sites_dir) {
        for entry in entries {
            let entry = match entry {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext != "conf" {
                continue;
            }
            let domain = match path.file_stem().and_then(|s| s.to_str()) {
                Some(value) => value.to_lowercase(),
                None => continue,
            };
            if !managed.contains(&domain) {
                let _ = fs::remove_file(path);
            }
        }
    }

    let site_logs_dir = sites_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sites_dir.to_path_buf())
        .join("logs")
        .join("nginx")
        .join("sites");
    if let Ok(entries) = fs::read_dir(&site_logs_dir) {
        for entry in entries {
            let entry = match entry {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = match path.file_name().and_then(|s| s.to_str()) {
                Some(value) => value.to_lowercase(),
                None => continue,
            };
            let domain = file_name
                .strip_suffix(".access.log")
                .or_else(|| file_name.strip_suffix(".error.log"))
                .unwrap_or_default()
                .to_string();
            if domain.is_empty() {
                continue;
            }
            if !managed.contains(&domain) {
                let _ = fs::remove_file(path);
            }
        }
    }

    Ok(())
}

fn ensure_hosts_elevator_scripts(sites_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    fs::create_dir_all(sites_dir).map_err(|e| format!("failed to create sites dir: {e}"))?;
    let ps1_path = sites_dir.join("_hosts_update.ps1");
    let bat_path = sites_dir.join("hosts-elevate.bat");
    let ps1_content = r##"param(
  [Parameter(Mandatory = $true)][string]$BlockFile
)
$hosts = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$start = "# Envloom generated Hosts. Do not change."
$end = "# End Envloom generated Hosts"
$newBlock = Get-Content -LiteralPath $BlockFile -Raw -ErrorAction Stop
$content = ""
if (Test-Path -LiteralPath $hosts) {
  $content = Get-Content -LiteralPath $hosts -Raw -ErrorAction SilentlyContinue
}
$escapedStart = [regex]::Escape($start)
$escapedEnd = [regex]::Escape($end)
$pattern = "$escapedStart[\s\S]*?$escapedEnd"
if ([regex]::IsMatch($content, $pattern)) {
  $updated = [regex]::Replace($content, $pattern, $newBlock)
} else {
  if ($content.Length -gt 0 -and -not $content.EndsWith("`r`n") -and -not $content.EndsWith("`n")) {
    $content += "`r`n"
  }
  $updated = $content + $newBlock + "`r`n"
}
Set-Content -LiteralPath $hosts -Value $updated -Encoding Ascii
"##;
    let bat_content = r#"@ECHO OFF
setlocal
if "%~1"=="" exit /b 1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0_hosts_update.ps1" -BlockFile "%~1"
if errorlevel 1 exit /b 1
endlocal
"#;
    fs::write(&ps1_path, ps1_content).map_err(|e| format!("failed to write hosts ps1 helper: {e}"))?;
    fs::write(&bat_path, bat_content).map_err(|e| format!("failed to write hosts bat helper: {e}"))?;
    Ok((ps1_path, bat_path))
}

fn hosts_block(domains: &[String]) -> String {
    let mut sorted: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    sorted.sort();
    sorted.dedup();
    let mut out = String::from("# Envloom generated Hosts. Do not change.\r\n");
    for domain in sorted {
        out.push_str(&format!("127.0.0.1 {domain}\r\n"));
    }
    out.push_str("# End Envloom generated Hosts");
    out
}

fn apply_hosts_block(content: &str, block: &str, domains: &[String]) -> String {
    let start = "# Envloom generated Hosts. Do not change.";
    let end = "# End Envloom generated Hosts";
    let mut without_block = content.to_string();
    if let Some(start_idx) = without_block.find(start) {
        if let Some(end_rel) = without_block[start_idx..].find(end) {
            let end_idx = start_idx + end_rel + end.len();
            let mut out = String::new();
            out.push_str(without_block[..start_idx].trim_end_matches(['\r', '\n']));
            if !without_block[end_idx..].trim().is_empty() {
                if !out.is_empty() {
                    out.push_str("\r\n");
                }
                out.push_str(without_block[end_idx..].trim_start_matches(['\r', '\n']));
            }
            without_block = out;
        }
    }

    let managed: HashSet<String> = domains.iter().map(|d| d.to_lowercase()).collect();
    let mut cleaned_lines: Vec<String> = Vec::new();
    for line in without_block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            cleaned_lines.push(line.to_string());
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            cleaned_lines.push(line.to_string());
            continue;
        }
        let ip = parts[0];
        if ip != "127.0.0.1" && ip != "::1" {
            cleaned_lines.push(line.to_string());
            continue;
        }
        let remaining_domains: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|domain| !managed.contains(&domain.to_lowercase()))
            .collect();
        if remaining_domains.is_empty() {
            continue;
        }
        cleaned_lines.push(format!("{ip} {}", remaining_domains.join(" ")));
    }

    let mut out = cleaned_lines.join("\r\n");
    out = out.trim_end_matches(['\r', '\n']).to_string();
    if !out.is_empty() {
        out.push_str("\r\n");
    }
    out.push_str(block);
    out.push_str("\r\n");
    out
}

fn sync_hosts_block(domains: Vec<String>, sites_dir: &Path) -> Result<(), String> {
    let hosts_path = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
    let (ps1_path, bat_path) = ensure_hosts_elevator_scripts(sites_dir)?;
    let current = fs::read_to_string(&hosts_path).unwrap_or_default();
    let block = hosts_block(&domains);
    let next = apply_hosts_block(&current, &block, &domains);
    if fs::write(&hosts_path, &next).is_ok() {
        return Ok(());
    }

    fs::create_dir_all(sites_dir).map_err(|e| format!("failed to create sites dir: {e}"))?;
    let block_file = sites_dir.join("_hosts_block.txt");
    fs::write(&block_file, &block).map_err(|e| format!("failed to write hosts block file: {e}"))?;
    let elevate_script = format!(
        "$args = @('-NoProfile','-ExecutionPolicy','Bypass','-File','{ps1}','-BlockFile','{block}'); \
         $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $args -Verb RunAs -PassThru -Wait; \
         if ($p.ExitCode -ne 0) {{ throw \"hosts helper failed with exit code $($p.ExitCode)\" }}",
        ps1 = ps_quote(&ps1_path.to_string_lossy()),
        block = ps_quote(&block_file.to_string_lossy())
    );
    run_powershell(&elevate_script)
        .map_err(|error| format!("failed to run elevated hosts helper: {error}"))?;

    let updated = fs::read_to_string(&hosts_path).unwrap_or_default();
    let has_start = updated.contains("# Envloom generated Hosts. Do not change.");
    let has_end = updated.contains("# End Envloom generated Hosts");
    if !has_start || !has_end {
        return Err(format!(
            "failed to update hosts block automatically (UAC may have been denied). Helper: {}",
            bat_path.to_string_lossy()
        ));
    }
    Ok(())
}

fn set_project_app_url(project_path: &Path, domain: &str, ssl_enabled: bool) -> Result<(), String> {
    let env_path = project_path.join(".env");
    if !env_path.exists() {
        return Ok(());
    }
    let scheme = if ssl_enabled { "https" } else { "http" };
    let app_url = format!("{scheme}://{domain}");
    let content = fs::read_to_string(&env_path).map_err(|e| format!("failed to read .env: {e}"))?;
    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with("APP_URL=") {
                found = true;
                format!("APP_URL={app_url}")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !found {
        lines.push(format!("APP_URL={app_url}"));
    }
    let mut next = lines.join("\n");
    next.push('\n');
    fs::write(env_path, next).map_err(|e| format!("failed to write .env: {e}"))?;
    Ok(())
}

fn resolve_sites_dir_from_php_install_dir(php_install_dir: &Path) -> PathBuf {
    if cfg!(debug_assertions) {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sites");
    }
    let bin_dir = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.to_path_buf());
    bin_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(bin_dir)
        .join("sites")
}

fn resolve_logs_dir_from_bin_root(bin_root: &Path) -> PathBuf {
    if cfg!(debug_assertions) {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("logs");
    }
    bin_root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| bin_root.to_path_buf())
        .join("logs")
}

fn initialize_and_start_mariadb_if_needed(
    install_dir: &PathBuf,
    config: &MariaDbConfig,
    log_path: Option<&PathBuf>,
) -> Result<(), String> {
    fn tail_text(content: &str, max_lines: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(max_lines);
        lines[start..].join("\n")
    }

    fn latest_mariadb_error_log(data_dir: &Path, logs_dir: &Path) -> Option<String> {
        for dir in [logs_dir, data_dir] {
            let entries = match fs::read_dir(dir) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if ext != "err" && ext != "log" {
                    continue;
                }
                let modified = match entry.metadata().ok().and_then(|m| m.modified().ok()) {
                    Some(value) => value,
                    None => continue,
                };
                match &newest {
                    None => newest = Some((modified, path)),
                    Some((current, _)) if modified > *current => newest = Some((modified, path)),
                    _ => {}
                }
            }
            if let Some((_, path)) = newest {
                if let Ok(raw) = fs::read_to_string(path) {
                    return Some(tail_text(&raw, 80));
                }
            }
        }
        None
    }

    fn wait_mariadb_running(install_dir: &PathBuf, port: u16, attempts: u32, sleep_ms: u64) -> bool {
        for _ in 0..attempts {
            if is_mariadb_listening_in_root(install_dir, port) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        false
    }

    let current_dir = install_dir.join("current");
    let mariadbd = current_dir.join("bin").join("mariadbd.exe");
    let defaults_file = current_dir.join("my.ini");
    if !mariadbd.exists() || !defaults_file.exists() {
        return Ok(());
    }
    let data_dir = current_dir.join("data");
    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.to_path_buf());
    let mariadb_logs_dir = resolve_logs_dir_from_bin_root(&bin_root).join("mariadb");
    let _ = fs::create_dir_all(&mariadb_logs_dir);
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir).map_err(|e| format!("failed creating mariadb data dir: {e}"))?;
    }
    let mysql_system_dir = data_dir.join("mysql");
    if !mysql_system_dir.exists() {
        let entries = fs::read_dir(&data_dir).map_err(|e| format!("failed reading mariadb data dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed reading mariadb data entry: {e}"))?;
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)
                    .map_err(|e| format!("failed cleaning mariadb data dir entry '{}': {e}", path.display()))?;
            } else {
                fs::remove_file(&path)
                    .map_err(|e| format!("failed cleaning mariadb data file entry '{}': {e}", path.display()))?;
            }
        }

        let mysql_install_db = current_dir.join("bin").join("mysql_install_db.exe");
        let install_db = current_dir.join("bin").join("mariadb-install-db.exe");

        if mysql_install_db.exists() {
            let mut args = vec![
                "-d".to_string(),
                data_dir.to_string_lossy().to_string(),
                "-P".to_string(),
                config.port.to_string(),
            ];
            if !config.root_password.trim().is_empty() {
                args.push("-p".to_string());
                args.push(config.root_password.clone());
            }
            let output = Command::new(&mysql_install_db)
                .args(args)
                .current_dir(&current_dir)
                .output()
                .map_err(|e| format!("failed to run {}: {e}", mysql_install_db.display()))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some(path) = log_path {
                    append_runtime_log(
                        path,
                        "ERROR",
                        "mariadb.init",
                        &format!(
                            "{} failed. stdout: {}. stderr: {}",
                            mysql_install_db.display(),
                            stdout,
                            stderr
                        ),
                    );
                }
                return Err(format!(
                    "{} failed. stdout: {}. stderr: {}",
                    mysql_install_db.display(),
                    stdout,
                    stderr
                ));
            }
        } else if install_db.exists() {
            let install_db_script = format!(
                "& '{exe}' --datadir='{data}' --basedir='{base}'",
                exe = ps_quote(&install_db.to_string_lossy()),
                data = ps_quote(&data_dir.to_string_lossy()),
                base = ps_quote(&current_dir.to_string_lossy())
            );
            if let Err(first_error) = run_powershell(&install_db_script) {
                let fallback_script = format!(
                    "& '{exe}' --datadir='{data}'",
                    exe = ps_quote(&install_db.to_string_lossy()),
                    data = ps_quote(&data_dir.to_string_lossy())
                );
                run_powershell(&fallback_script).map_err(|fallback_error| {
                    if let Some(path) = log_path {
                        append_runtime_log(
                            path,
                            "ERROR",
                            "mariadb.init",
                            &format!(
                                "install-db failed. first: {}. fallback: {}",
                                first_error, fallback_error
                            ),
                        );
                    }
                    format!(
                        "mariadb initialization failed. install-db: {first_error}. fallback: {fallback_error}"
                    )
                })?;
            }
        } else {
            return Err("mysql_install_db.exe / mariadb-install-db.exe not found in current MariaDB runtime".to_string());
        }
        if !mysql_system_dir.exists() {
            return Err(format!(
                "mariadb initialization did not create system tables in '{}'",
                mysql_system_dir.display()
            ));
        }
    }
    if is_mariadb_listening_in_root(install_dir, config.port) {
        return Ok(());
    }
    let start_script = format!(
        "$cfg='{cfg}'; $data='{data}'; $args=@(\"--defaults-file=$cfg\",\"--datadir=$data\",\"--port={port}\"); Start-Process -WindowStyle Hidden -FilePath '{exe}' -WorkingDirectory '{cwd}' -ArgumentList $args | Out-Null",
        exe = ps_quote(&mariadbd.to_string_lossy()),
        cwd = ps_quote(&current_dir.to_string_lossy()),
        cfg = ps_quote(&defaults_file.to_string_lossy()),
        data = ps_quote(&data_dir.to_string_lossy()),
        port = config.port
    );
    run_powershell(&start_script)?;
    if !wait_mariadb_running(install_dir, config.port, 12, 350) {
        let fallback_script = format!(
            "$data='{data}'; $args=@(\"--datadir=$data\",\"--port={port}\",\"--bind-address=127.0.0.1\"); Start-Process -WindowStyle Hidden -FilePath '{exe}' -WorkingDirectory '{cwd}' -ArgumentList $args | Out-Null",
            exe = ps_quote(&mariadbd.to_string_lossy()),
            cwd = ps_quote(&current_dir.to_string_lossy()),
            data = ps_quote(&data_dir.to_string_lossy()),
            port = config.port
        );
        run_powershell(&fallback_script)?;
        if !wait_mariadb_running(install_dir, config.port, 12, 350) {
            let log_tail = latest_mariadb_error_log(&data_dir, &mariadb_logs_dir)
                .unwrap_or_else(|| "no .err/.log file found in mariadb logs/data dir".to_string());
            if let Some(path) = log_path {
                append_runtime_log(path, "ERROR", "mariadb.start", &format!("MariaDB failed to stay running. Error log tail:\n{log_tail}"));
            }
            return Err(format!("mariadb process exits after start. Error log tail:\n{log_tail}"));
        }
    }
    if let Some(path) = log_path {
        append_runtime_log(path, "INFO", "mariadb.start", "MariaDB started from current runtime");
    }
    Ok(())
}

fn stop_mariadb_if_running(install_dir: &PathBuf, config: &MariaDbConfig) -> Result<(), String> {
    let current_dir = install_dir.join("current");
    let mysqladmin = current_dir.join("bin").join("mysqladmin.exe");
    let mariadb_admin = current_dir.join("bin").join("mariadb-admin.exe");
    let admin_bin = if mysqladmin.exists() {
        Some(mysqladmin)
    } else if mariadb_admin.exists() {
        Some(mariadb_admin)
    } else {
        None
    };

    let was_listening = is_mariadb_listening_in_root(install_dir, config.port);
    if was_listening {
        if let Some(admin) = admin_bin {
            let mut args = vec![
                "-h".to_string(),
                "127.0.0.1".to_string(),
                "-P".to_string(),
                config.port.to_string(),
                "-u".to_string(),
                "root".to_string(),
                "shutdown".to_string(),
            ];
            if !config.root_password.trim().is_empty() {
                args.insert(6, format!("-p{}", config.root_password));
            }
            let _ = Command::new(admin).args(args).current_dir(&current_dir).output();
        }
    }

    // The running process may resolve to the real version path (e.g. mariadb\12.2\bin\mariadbd.exe)
    // instead of the "current" symlink path, so kill by install root as a fallback.
    let mariadbd = current_dir.join("bin").join("mariadbd.exe");
    if mariadbd.exists() {
        let _ = stop_processes_by_exact_path(&mariadbd);
    }
    let stop_script = format!(
        "$root='{root}'; \
         Get-Process -Name 'mariadbd' -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath -like ($root + '*') }} | \
         ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}",
        root = ps_quote(&install_dir.to_string_lossy())
    );
    let _ = run_powershell(&stop_script);

    if was_listening {
        for _ in 0..20 {
            if !is_mariadb_listening_in_root(install_dir, config.port) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        return Err(format!(
            "mariadb did not stop cleanly; port {} is still open",
            config.port
        ));
    }
    Ok(())
}

fn run_mariadb_sql(
    current_dir: &PathBuf,
    port: u16,
    password: Option<&str>,
    sql: &str,
) -> Result<String, String> {
    let mariadb_client = current_dir.join("bin").join("mariadb.exe");
    if !mariadb_client.exists() {
        return Err(format!("mariadb client not found: {}", mariadb_client.display()));
    }
    let mut args = vec![
        "-h".to_string(),
        "127.0.0.1".to_string(),
        "-P".to_string(),
        port.to_string(),
        "-u".to_string(),
        "root".to_string(),
        "-e".to_string(),
        sql.to_string(),
    ];
    if let Some(pwd) = password {
        args.push(format!("-p{pwd}"));
    }
    let output = Command::new(&mariadb_client)
        .args(args)
        .current_dir(current_dir)
        .output()
        .map_err(|e| format!("failed to run mariadb client: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(format!("mariadb client failed. stdout: {stdout}. stderr: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn apply_mariadb_root_password_if_needed(
    install_dir: &PathBuf,
    config: &MariaDbConfig,
    log_path: Option<&PathBuf>,
) -> Result<(), String> {
    if config.root_password.trim().is_empty() {
        return Ok(());
    }
    if !is_mariadb_listening_in_root(install_dir, config.port) {
        return Ok(());
    }
    let current_dir = install_dir.join("current");
    let test_sql = "SELECT 1;";
    if run_mariadb_sql(&current_dir, config.port, Some(config.root_password.as_str()), test_sql).is_ok() {
        return Ok(());
    }
    if run_mariadb_sql(&current_dir, config.port, None, test_sql).is_err() {
        if let Some(path) = log_path {
            append_runtime_log(
                path,
                "ERROR",
                "mariadb.password",
                "Could not authenticate as root without password to apply configured password",
            );
        }
        return Err(
            "could not authenticate as root to apply password; start MariaDB with empty root password first"
                .to_string(),
        );
    }
    let mysqladmin = current_dir.join("bin").join("mysqladmin.exe");
    let mariadb_admin = current_dir.join("bin").join("mariadb-admin.exe");
    let admin_bin = if mysqladmin.exists() {
        mysqladmin
    } else if mariadb_admin.exists() {
        mariadb_admin
    } else {
        return Err("neither mysqladmin.exe nor mariadb-admin.exe found in current runtime".to_string());
    };
    let output = Command::new(&admin_bin)
        .args([
            "-h",
            "127.0.0.1",
            "-P",
            &config.port.to_string(),
            "-u",
            "root",
            "password",
            &config.root_password,
        ])
        .current_dir(&current_dir)
        .output()
        .map_err(|e| format!("failed to run {}: {e}", admin_bin.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if let Some(path) = log_path {
            append_runtime_log(
                path,
                "ERROR",
                "mariadb.password",
                &format!(
                    "{} failed. stdout: {}. stderr: {}",
                    admin_bin.display(),
                    stdout,
                    stderr
                ),
            );
        }
        return Err(format!(
            "{} failed. stdout: {}. stderr: {}",
            admin_bin.display(),
            stdout,
            stderr
        ));
    }
    run_mariadb_sql(&current_dir, config.port, Some(config.root_password.as_str()), test_sql)?;
    if let Some(path) = log_path {
        append_runtime_log(path, "INFO", "mariadb.password", "Root password applied/validated");
    }
    Ok(())
}

fn sync_local_mariadb_installations(install_dir: &PathBuf, config: &mut MariaDbConfig) -> Result<(), String> {
    if !install_dir.exists() {
        fs::create_dir_all(install_dir).map_err(|e| format!("failed to create mariadb install dir: {e}"))?;
    }
    let mut discovered_installed: HashMap<String, Vec<String>> = HashMap::new();
    let entries = fs::read_dir(install_dir).map_err(|e| format!("failed to read mariadb install dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read mariadb dir entry: {e}"))?;
        if !entry.path().is_dir() {
            continue;
        }
        let line = entry.file_name().to_string_lossy().to_string();
        if version_line(&format!("{line}.0")).is_none() {
            continue;
        }
        let line_dir = entry.path();
        let server_exe = line_dir.join("bin").join("mariadbd.exe");
        let client_exe = line_dir.join("bin").join("mariadb.exe");
        if !server_exe.exists() || !client_exe.exists() {
            let _ = fs::remove_dir_all(&line_dir);
            continue;
        }
        let version = detect_mariadb_version_from_binary(&line_dir).unwrap_or(line);
        discovered_installed.insert(
            entry.file_name().to_string_lossy().to_string(),
            vec![version],
        );
    }
    config.installed = discovered_installed;
    if let Some(current_line) = config.current_line.clone() {
        if !config.installed.contains_key(&current_line) {
            config.current_line = None;
        }
    }
    Ok(())
}

fn build_mariadb_catalog(
    config: &MariaDbConfig,
    latest: &HashMap<String, MariaDbReleaseBuild>,
) -> Vec<MariaDbLineRuntime> {
    let mut lines: Vec<String> = latest.keys().cloned().collect();
    for line in config.installed.keys() {
        if !lines.contains(line) {
            lines.push(line.clone());
        }
    }
    lines.sort_by(|a, b| {
        if is_version_gt(a, b) {
            std::cmp::Ordering::Less
        } else if is_version_gt(b, a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    lines
        .into_iter()
        .map(|line| {
            let latest_version = latest.get(&line).map(|value| value.version.clone());
            let installed_versions = config.installed.get(&line).cloned().unwrap_or_default();
            MariaDbLineRuntime {
                line,
                latest_version,
                installed_versions,
            }
        })
        .collect()
}

fn build_php_catalog(config: &PhpConfig, latest: &HashMap<String, PhpReleaseBuild>) -> Vec<PhpLineRuntime> {
    let mut lines: Vec<String> = latest.keys().cloned().collect();
    for line in config.installed.keys() {
        if !lines.contains(line) {
            lines.push(line.clone());
        }
    }
    lines.sort_by(|a, b| {
        if is_version_gt(a, b) {
            std::cmp::Ordering::Less
        } else if is_version_gt(b, a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });

    lines
        .into_iter()
        .map(|line| {
            let latest_data = latest.get(&line);
            let installed_versions = config.installed.get(&line).cloned().unwrap_or_default();
            PhpLineRuntime {
                line: line.clone(),
                latest_version: latest_data.map(|value| value.version.clone()),
                latest_url: latest_data.map(|value| value.url.clone()),
                installed_versions,
                active_version: config.active.get(&line).cloned().filter(|v| !v.is_empty()),
                fpm_port: line_port(config.base_port, &line),
            }
        })
        .collect()
}

#[tauri::command]
fn list_runtimes(state: tauri::State<'_, AppState>) -> Result<Vec<RuntimeResponse>, String> {
    let guard = state
        .runtimes
        .lock()
        .map_err(|_| "failed to lock runtime state".to_string())?;
    Ok(sorted_response(&guard.store))
}

#[tauri::command]
fn set_active_runtime(
    state: tauri::State<'_, AppState>,
    runtime: String,
    version: String,
) -> Result<Vec<RuntimeResponse>, String> {
    let runtime_key = runtime.to_lowercase();
    let mut guard = state
        .runtimes
        .lock()
        .map_err(|_| "failed to lock runtime state".to_string())?;

    let record = guard
        .store
        .runtimes
        .get_mut(&runtime_key)
        .ok_or_else(|| format!("runtime not found: {runtime_key}"))?;

    if !record.installed.iter().any(|v| v == &version) {
        return Err(format!("version {version} is not installed for {runtime_key}"));
    }

    record.active = version;
    save_store(&guard.path, &guard.store)?;
    Ok(sorted_response(&guard.store))
}

#[tauri::command]
fn add_runtime_version(
    state: tauri::State<'_, AppState>,
    runtime: String,
    version: String,
) -> Result<Vec<RuntimeResponse>, String> {
    let runtime_key = runtime.to_lowercase();
    let version = version.trim().to_string();
    if version.is_empty() {
        return Err("version cannot be empty".to_string());
    }

    let mut guard = state
        .runtimes
        .lock()
        .map_err(|_| "failed to lock runtime state".to_string())?;
    let record = guard
        .store
        .runtimes
        .entry(runtime_key.clone())
        .or_insert_with(|| RuntimeRecord {
            active: version.clone(),
            installed: vec![],
        });

    if !record.installed.iter().any(|v| v == &version) {
        record.installed.push(version.clone());
        record.installed.sort();
    }
    if record.active.is_empty() {
        record.active = version;
    }

    save_store(&guard.path, &guard.store)?;
    Ok(sorted_response(&guard.store))
}

#[tauri::command]
fn remove_runtime_version(
    state: tauri::State<'_, AppState>,
    runtime: String,
    version: String,
) -> Result<Vec<RuntimeResponse>, String> {
    let runtime_key = runtime.to_lowercase();
    let mut guard = state
        .runtimes
        .lock()
        .map_err(|_| "failed to lock runtime state".to_string())?;
    let record = guard
        .store
        .runtimes
        .get_mut(&runtime_key)
        .ok_or_else(|| format!("runtime not found: {runtime_key}"))?;

    if record.active == version {
        return Err("cannot remove the active version".to_string());
    }
    record.installed.retain(|v| v != &version);
    save_store(&guard.path, &guard.store)?;
    Ok(sorted_response(&guard.store))
}

#[tauri::command]
fn list_sites(state: tauri::State<'_, AppState>) -> Result<Vec<SiteRecord>, String> {
    let guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;
    Ok(sorted_sites(&guard.store))
}

#[tauri::command]
fn site_pick_existing_folder() -> Result<Option<String>, String> {
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Select an existing project folder'
$dialog.ShowNewFolderButton = $false
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $dialog.SelectedPath }
"#;
    let output = run_powershell(script)?;
    let path = output.trim().to_string();
    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

#[tauri::command]
fn site_inspect_path(path: String) -> Result<SitePathInspection, String> {
    let raw = path.trim();
    if raw.is_empty() {
        return Ok(SitePathInspection {
            exists: false,
            is_directory: false,
            suggested_name: None,
            framework: "unknown".to_string(),
            is_php_project: false,
        });
    }
    let p = PathBuf::from(raw);
    let exists = p.exists();
    let is_directory = p.is_dir();
    let suggested_name = p
        .file_name()
        .and_then(|v| v.to_str())
        .map(|v| v.to_string())
        .filter(|v| !v.trim().is_empty());
    let (framework, is_php_project) = if exists && is_directory {
        detect_framework_from_path(&p)
    } else {
        ("unknown".to_string(), false)
    };
    Ok(SitePathInspection {
        exists,
        is_directory,
        suggested_name,
        framework,
        is_php_project,
    })
}

#[tauri::command]
async fn create_site(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    payload: SiteCreateRequest,
) -> Result<Vec<SiteRecord>, String> {
    let name = payload.name.trim().to_string();
    let domain = payload.domain.trim().to_lowercase();
    let path = payload.path.trim().to_string();
    let php_version = payload.php_version.trim().to_string();
    let node_version = payload.node_version.trim().to_string();
    if name.is_empty() {
        return Err("site name is required".to_string());
    }
    if domain.is_empty() {
        return Err("site domain is required".to_string());
    }
    if path.is_empty() {
        return Err("site path is required".to_string());
    }
    if php_version.is_empty() {
        return Err("php version is required".to_string());
    }
    if node_version.is_empty() {
        return Err("node version is required".to_string());
    }
    let path_buf = PathBuf::from(&path);
    let starter_kit = normalize_starter_kit(payload.starter_kit.as_deref());
    emit_site_provision_output(
        &app,
        &format!(
            "Starting site creation: {} (php {}, ssl={})",
            domain, php_version, payload.ssl_enabled
        ),
    );
    if payload.linked {
        if !path_buf.exists() {
            return Err(format!("linked project path does not exist: {path}"));
        }
        emit_site_provision_output(&app, "Action: linked existing project path.");
    } else {
        let (php_install_dir, template_dir, php_config, log_path) = {
            let php_guard = state
                .php
                .lock()
                .map_err(|_| "failed to lock php state".to_string())?;
            (
                php_guard.install_dir.clone(),
                php_guard.template_dir.clone(),
                php_guard.config.clone(),
                state.log_path.clone(),
            )
        };
        let path_for_task = path_buf.clone();
        let php_version_for_task = php_version.clone();
        let starter_for_task = starter_kit.clone();
        let app_for_task = app.clone();
        tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
            apply_php_ini_to_line(&php_install_dir, &template_dir, &php_version_for_task, &php_config)?;
            emit_site_provision_output(
                &app_for_task,
                &format!(
                    "Provisioning site at {} with PHP {} and starter {:?}",
                    path_for_task.to_string_lossy(),
                    php_version_for_task,
                    starter_for_task
                ),
            );
            provision_new_laravel_site(
                &app_for_task,
                &php_install_dir,
                &path_for_task,
                &php_version_for_task,
                starter_for_task.as_deref(),
            )?;
            emit_site_provision_output(&app_for_task, "Provisioning commands completed.");
            Ok(())
        })
        .await
        .map_err(|e| {
            append_runtime_log(&log_path, "ERROR", "sites.create", &format!("task join failed: {e}"));
            format!("site provisioning task failed: {e}")
        })??;
    }

    let mut guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;

    if guard
        .store
        .sites
        .iter()
        .any(|site| site.domain.eq_ignore_ascii_case(&domain))
    {
        return Err(format!("site domain already exists: {domain}"));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("failed to read clock: {e}"))?
        .as_millis();
    let id = format!("{}-{timestamp}", domain.replace('.', "-"));
    let record = SiteRecord {
        id,
        name,
        domain: domain.clone(),
        linked: payload.linked,
        ssl_enabled: payload.ssl_enabled,
        path: path.clone(),
        php_version: php_version.clone(),
        node_version: node_version.clone(),
        starter_kit: starter_kit.clone(),
    };
    guard.store.sites.push(record);
    save_sites_store(&guard.path, &guard.store)?;
    let sites = sorted_sites(&guard.store);
    drop(guard);

    let log_path = state.log_path.clone();
    let path_for_setup = path_buf.clone();
    let domain_for_setup = domain.clone();
    let php_line_for_setup = php_version.clone();
    let ssl_for_setup = payload.ssl_enabled;
    let (php_install_dir, php_base_port) = {
        let php_guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        (php_guard.install_dir.clone(), php_guard.config.base_port)
    };
    let bin_dir = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    let nginx_root = bin_dir.join("nginx");
    let sites_dir = resolve_sites_dir_from_php_install_dir(&php_install_dir);
    let fpm_port = line_port(php_base_port, &php_line_for_setup);

    if let Err(error) = write_nginx_site_config(
        &nginx_root,
        &sites_dir,
        &domain_for_setup,
        &path_for_setup,
        fpm_port,
        ssl_for_setup,
    )
        .and_then(|_| reload_nginx_if_running(&nginx_root))
    {
        append_runtime_log(&log_path, "ERROR", "sites.nginx", &error);
        return Err(format!("site created but nginx setup failed: {error}"));
    }
    let domains: Vec<String> = sites.iter().map(|site| site.domain.clone()).collect();
    let _ = reconcile_nginx_site_configs(&sites_dir, &domains);
    if let Err(error) = sync_hosts_block(domains, &sites_dir) {
        append_runtime_log(&log_path, "ERROR", "sites.hosts", &error);
        return Err(format!("site created but hosts setup failed: {error}"));
    }
    if !payload.linked {
        if let Err(error) = set_project_app_url(&path_for_setup, &domain_for_setup, ssl_for_setup) {
            append_runtime_log(&log_path, "ERROR", "sites.env", &error);
            return Err(format!("site created but .env update failed: {error}"));
        }
    }

    emit_site_provision_output(&app, "Site setup completed successfully.");

    Ok(sites)
}

#[tauri::command]
fn delete_site(state: tauri::State<'_, AppState>, payload: SiteDeleteRequest) -> Result<Vec<SiteRecord>, String> {
    let site_id = payload.site_id.trim().to_string();
    if site_id.is_empty() {
        return Err("site id is required".to_string());
    }

    let (to_delete, log_path) = {
        let guard = state
            .sites
            .lock()
            .map_err(|_| "failed to lock sites state".to_string())?;
        let found = guard
            .store
            .sites
            .iter()
            .find(|site| site.id == site_id)
            .cloned()
            .ok_or_else(|| format!("site not found: {site_id}"))?;
        (found, state.log_path.clone())
    };

    if payload.delete_files {
        let site_path = PathBuf::from(&to_delete.path);
        if site_path.exists() {
            if site_path.is_dir() {
                fs::remove_dir_all(&site_path)
                    .map_err(|e| format!("failed to delete site directory {}: {e}", to_delete.path))?;
            } else {
                fs::remove_file(&site_path)
                    .map_err(|e| format!("failed to delete site file {}: {e}", to_delete.path))?;
            }
            append_runtime_log(
                &log_path,
                "INFO",
                "sites.delete.files",
                &format!("Deleted site files for {} at {}", to_delete.domain, to_delete.path),
            );
        }
    }

    let mut guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;
    let before = guard.store.sites.len();
    guard.store.sites.retain(|site| site.id != site_id);
    if guard.store.sites.len() == before {
        return Err(format!("site not found: {site_id}"));
    }
    save_sites_store(&guard.path, &guard.store)?;
    let remaining = sorted_sites(&guard.store);
    append_runtime_log(
        &log_path,
        "INFO",
        "sites.delete",
        &format!(
            "Deleted site {} (delete_files={})",
            to_delete.domain, payload.delete_files
        ),
    );
    drop(guard);

    let php_install_dir = {
        let php_guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        php_guard.install_dir.clone()
    };
    let sites_dir = resolve_sites_dir_from_php_install_dir(&php_install_dir);
    let domains: Vec<String> = remaining.iter().map(|site| site.domain.clone()).collect();
    let _ = reconcile_nginx_site_configs(&sites_dir, &domains);
    if let Err(error) = sync_hosts_block(domains, &sites_dir) {
        append_runtime_log(&log_path, "ERROR", "sites.delete.hosts", &error);
        return Err(error);
    }
    Ok(remaining)
}

#[tauri::command]
fn logs_tail(
    state: tauri::State<'_, AppState>,
    limit: Option<usize>,
    contains: Option<String>,
) -> Result<Vec<String>, String> {
    let max_lines = limit.unwrap_or(120).clamp(1, 2000);
    let raw = fs::read_to_string(&state.log_path)
        .map_err(|e| format!("failed to read runtime log: {e}"))?;
    let mut lines: Vec<String> = raw.lines().map(|line| line.to_string()).collect();
    if let Some(pattern) = contains {
        let pattern = pattern.trim().to_string();
        if !pattern.is_empty() {
            lines.retain(|line| line.contains(&pattern));
        }
    }
    if lines.len() > max_lines {
        let start = lines.len() - max_lines;
        lines = lines[start..].to_vec();
    }
    Ok(lines)
}

#[tauri::command]
fn logs_list_files(state: tauri::State<'_, AppState>) -> Result<Vec<LogFileItem>, String> {
    let logs_dir = state
        .log_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to resolve logs directory".to_string())?;
    if !logs_dir.exists() {
        return Ok(vec![]);
    }

    let mut out: Vec<LogFileItem> = Vec::new();
    let mut push_file = |path: PathBuf| {
        if !path.is_file() {
            return;
        }
        let rel = match path.strip_prefix(&logs_dir) {
            Ok(value) => value,
            Err(_) => return,
        };
        let rel_norm = rel.to_string_lossy().replace('\\', "/");
        let mut category = "binary".to_string();
        let mut group = "general".to_string();
        let label: String;

        if rel_norm.eq_ignore_ascii_case("runtime.log") {
            category = "runtime".to_string();
            group = "runtime".to_string();
            label = "runtime.log".to_string();
        } else if rel_norm.starts_with("nginx/sites/") {
            category = "site".to_string();
            group = "nginx".to_string();
            label = rel
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&rel_norm)
                .to_string();
        } else {
            let mut segments = rel_norm.split('/');
            if let Some(first) = segments.next() {
                group = first.to_string();
            }
            label = rel
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&rel_norm)
                .to_string();
        }
        out.push(LogFileItem {
            id: rel_norm.clone(),
            category,
            group,
            label,
            relative_path: rel_norm,
        });
    };

    if let Ok(entries) = fs::read_dir(&logs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                push_file(path);
                continue;
            }
            if path.is_dir() {
                if let Ok(level2) = fs::read_dir(&path) {
                    for entry2 in level2.flatten() {
                        let path2 = entry2.path();
                        if path2.is_file() {
                            push_file(path2);
                            continue;
                        }
                        if path2.is_dir() {
                            if let Ok(level3) = fs::read_dir(&path2) {
                                for entry3 in level3.flatten() {
                                    let path3 = entry3.path();
                                    if path3.is_file() {
                                        push_file(path3);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    out.sort_by(|a, b| {
        let category_order = |value: &str| match value {
            "runtime" => 0,
            "binary" => 1,
            "site" => 2,
            _ => 9,
        };
        category_order(&a.category)
            .cmp(&category_order(&b.category))
            .then(a.group.cmp(&b.group))
            .then(a.label.cmp(&b.label))
    });
    Ok(out)
}

#[tauri::command]
fn logs_read_file(
    state: tauri::State<'_, AppState>,
    relative_path: String,
    limit: Option<usize>,
) -> Result<Vec<String>, String> {
    let rel = relative_path.trim().replace('\\', "/");
    if rel.is_empty() {
        return Err("relative path is required".to_string());
    }
    if rel.contains("..") || rel.starts_with('/') {
        return Err("invalid log path".to_string());
    }
    let logs_dir = state
        .log_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to resolve logs directory".to_string())?;
    let target = logs_dir.join(rel);
    if !target.exists() || !target.is_file() {
        return Err(format!("log file not found: {}", target.to_string_lossy()));
    }
    let raw = fs::read_to_string(&target).map_err(|e| format!("failed to read log file: {e}"))?;
    let max_lines = limit.unwrap_or(500).clamp(1, 5000);
    let mut lines: Vec<String> = raw.lines().map(|line| line.to_string()).collect();
    if lines.len() > max_lines {
        let start = lines.len() - max_lines;
        lines = lines[start..].to_vec();
    }
    Ok(lines)
}

#[tauri::command]
fn site_regenerate_ssl(state: tauri::State<'_, AppState>, site_id: String) -> Result<Vec<SiteRecord>, String> {
    let site_id = site_id.trim().to_string();
    if site_id.is_empty() {
        return Err("site id is required".to_string());
    }

    let site = {
        let guard = state
            .sites
            .lock()
            .map_err(|_| "failed to lock sites state".to_string())?;
        guard
            .store
            .sites
            .iter()
            .find(|item| item.id == site_id)
            .cloned()
            .ok_or_else(|| format!("site not found: {site_id}"))?
    };
    if !site.ssl_enabled {
        return Err("SSL is disabled for this site".to_string());
    }

    let (php_install_dir, php_base_port) = {
        let php_guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        (php_guard.install_dir.clone(), php_guard.config.base_port)
    };
    let bin_dir = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    let nginx_root = bin_dir.join("nginx");
    let sites_dir = resolve_sites_dir_from_php_install_dir(&php_install_dir);
    let fpm_port = line_port(php_base_port, &site.php_version);
    let site_path = PathBuf::from(&site.path);
    let log_path = state.log_path.clone();

    write_nginx_site_config(
        &nginx_root,
        &sites_dir,
        &site.domain,
        &site_path,
        fpm_port,
        true,
    )
    .and_then(|_| reload_nginx_if_running(&nginx_root))
    .and_then(|_| {
        if site.linked {
            Ok(())
        } else {
            set_project_app_url(&site_path, &site.domain, true)
        }
    })
    .map_err(|error| {
        append_runtime_log(&log_path, "ERROR", "sites.ssl.regenerate", &error);
        error
    })?;

    append_runtime_log(
        &log_path,
        "INFO",
        "sites.ssl.regenerate",
        &format!("SSL regenerated for {}", site.domain),
    );

    let guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;
    let rows = sorted_sites(&guard.store);
    drop(guard);
    let domains: Vec<String> = rows.iter().map(|site| site.domain.clone()).collect();
    let _ = reconcile_nginx_site_configs(&sites_dir, &domains);
    if let Err(error) = sync_hosts_block(domains, &sites_dir) {
        append_runtime_log(&log_path, "ERROR", "sites.ssl.regenerate.hosts", &error);
        return Err(error);
    }
    let guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;
    Ok(sorted_sites(&guard.store))
}

#[tauri::command]
fn site_set_ssl(
    state: tauri::State<'_, AppState>,
    site_id: String,
    ssl_enabled: bool,
) -> Result<Vec<SiteRecord>, String> {
    let site_id = site_id.trim().to_string();
    if site_id.is_empty() {
        return Err("site id is required".to_string());
    }

    let (site, rows_after_update) = {
        let mut guard = state
            .sites
            .lock()
            .map_err(|_| "failed to lock sites state".to_string())?;
        let Some(target) = guard.store.sites.iter_mut().find(|item| item.id == site_id) else {
            return Err(format!("site not found: {site_id}"));
        };
        target.ssl_enabled = ssl_enabled;
        let site = target.clone();
        save_sites_store(&guard.path, &guard.store)?;
        let rows = sorted_sites(&guard.store);
        (site, rows)
    };

    let (php_install_dir, php_base_port) = {
        let php_guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        (php_guard.install_dir.clone(), php_guard.config.base_port)
    };
    let bin_dir = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    let nginx_root = bin_dir.join("nginx");
    let sites_dir = resolve_sites_dir_from_php_install_dir(&php_install_dir);
    let fpm_port = line_port(php_base_port, &site.php_version);
    let site_path = PathBuf::from(&site.path);
    let log_path = state.log_path.clone();

    write_nginx_site_config(
        &nginx_root,
        &sites_dir,
        &site.domain,
        &site_path,
        fpm_port,
        ssl_enabled,
    )
    .and_then(|_| reload_nginx_if_running(&nginx_root))
    .and_then(|_| {
        if site.linked {
            Ok(())
        } else {
            set_project_app_url(&site_path, &site.domain, ssl_enabled)
        }
    })
    .map_err(|error| {
        append_runtime_log(&log_path, "ERROR", "sites.ssl.set", &error);
        error
    })?;

    let domains: Vec<String> = rows_after_update.iter().map(|item| item.domain.clone()).collect();
    let _ = reconcile_nginx_site_configs(&sites_dir, &domains);
    if let Err(error) = sync_hosts_block(domains, &sites_dir) {
        append_runtime_log(&log_path, "ERROR", "sites.ssl.set.hosts", &error);
        return Err(error);
    }

    let guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;
    Ok(sorted_sites(&guard.store))
}

#[tauri::command]
fn site_set_php_version(
    state: tauri::State<'_, AppState>,
    site_id: String,
    php_version: String,
) -> Result<Vec<SiteRecord>, String> {
    let site_id = site_id.trim().to_string();
    if site_id.is_empty() {
        return Err("site id is required".to_string());
    }
    let php_version = php_version.trim().to_string();
    if php_version.is_empty() {
        return Err("php version is required".to_string());
    }

    let (site, rows_after_update) = {
        let mut guard = state
            .sites
            .lock()
            .map_err(|_| "failed to lock sites state".to_string())?;
        let Some(target) = guard.store.sites.iter_mut().find(|item| item.id == site_id) else {
            return Err(format!("site not found: {site_id}"));
        };
        target.php_version = php_version.clone();
        let site = target.clone();
        save_sites_store(&guard.path, &guard.store)?;
        let rows = sorted_sites(&guard.store);
        (site, rows)
    };

    let (php_install_dir, php_base_port) = {
        let php_guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        (php_guard.install_dir.clone(), php_guard.config.base_port)
    };
    let selected_php = php_install_dir.join(&php_version).join("php.exe");
    if !selected_php.exists() {
        return Err(format!("php line {php_version} is not installed"));
    }
    let bin_dir = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    let nginx_root = bin_dir.join("nginx");
    let sites_dir = resolve_sites_dir_from_php_install_dir(&php_install_dir);
    let fpm_port = line_port(php_base_port, &site.php_version);
    let site_path = PathBuf::from(&site.path);
    let log_path = state.log_path.clone();

    write_nginx_site_config(
        &nginx_root,
        &sites_dir,
        &site.domain,
        &site_path,
        fpm_port,
        site.ssl_enabled,
    )
    .and_then(|_| reload_nginx_if_running(&nginx_root))
    .map_err(|error| {
        append_runtime_log(&log_path, "ERROR", "sites.php.set", &error);
        error
    })?;

    append_runtime_log(
        &log_path,
        "INFO",
        "sites.php.set",
        &format!("PHP line for site {} set to {}", site.domain, site.php_version),
    );

    let domains: Vec<String> = rows_after_update.iter().map(|item| item.domain.clone()).collect();
    let _ = reconcile_nginx_site_configs(&sites_dir, &domains);
    if let Err(error) = sync_hosts_block(domains, &sites_dir) {
        append_runtime_log(&log_path, "ERROR", "sites.php.set.hosts", &error);
        return Err(error);
    }

    let guard = state
        .sites
        .lock()
        .map_err(|_| "failed to lock sites state".to_string())?;
    Ok(sorted_sites(&guard.store))
}

#[tauri::command]
fn php_get_catalog(state: tauri::State<'_, AppState>) -> Result<PhpCatalogResponse, String> {
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let before = guard.config.clone();
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;
    let latest = latest_builds_with_fallback(&guard.cache_path);
    if guard.config != before {
        save_php_config(&guard.config_path, &guard.config)?;
    }
    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_set_base_port(state: tauri::State<'_, AppState>, base_port: u16) -> Result<PhpCatalogResponse, String> {
    if !(1024..=65000).contains(&base_port) {
        return Err("base port must be between 1024 and 65000".to_string());
    }
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;
    guard.config.base_port = base_port;
    apply_php_ini_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    restart_php_fpm_services(&guard.install_dir, &guard.config)?;
    save_php_config(&guard.config_path, &guard.config)?;
    let latest = latest_builds_with_fallback(&guard.cache_path);
    Ok(PhpCatalogResponse {
        base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_install_latest(state: tauri::State<'_, AppState>, line: String) -> Result<PhpCatalogResponse, String> {
    let mariadb_install_dir = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;
    let latest = latest_builds_with_fallback(&guard.cache_path);
    let build = latest
        .get(&line)
        .cloned()
        .ok_or_else(|| format!("could not find latest TS x64 build for PHP {line}"))?;
    install_php_line_build_with_progress(&guard.install_dir, &line, &build, |_| {})?;
    let line_dir = guard.install_dir.join(&line);
    apply_php_ini_to_line(&guard.install_dir, &guard.template_dir, &line, &guard.config)?;

    let installed_version = detect_php_version_from_binary(&line_dir).unwrap_or(build.version);
    guard
        .config
        .installed
        .insert(line.clone(), vec![installed_version.clone()]);
    guard
        .config
        .active
        .insert(line.clone(), installed_version);
    guard.config.current_line = Some(line.clone());
    set_php_current_link(&guard.install_dir, &line)?;
    restart_php_fpm_services(&guard.install_dir, &guard.config)?;
    save_php_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&guard.install_dir, &mariadb_install_dir);

    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_uninstall_line(state: tauri::State<'_, AppState>, line: String) -> Result<PhpCatalogResponse, String> {
    let mariadb_install_dir = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;

    if guard.config.current_line.as_deref() == Some(line.as_str()) {
        return Err(format!("cannot uninstall current PHP line {line}; select another current line first"));
    }
    if !guard.config.installed.contains_key(&line) {
        return Err(format!("php line {line} is not installed"));
    }

    let line_dir = guard.install_dir.join(&line);
    let _ = stop_processes_by_exact_path(&line_dir.join("php-cgi.exe"));
    if line_dir.exists() {
        fs::remove_dir_all(&line_dir)
            .map_err(|e| format!("failed to remove php line directory '{}': {e}", line_dir.display()))?;
    }

    guard.config.installed.remove(&line);
    guard.config.active.remove(&line);
    apply_php_ini_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    restart_php_fpm_services(&guard.install_dir, &guard.config)?;
    save_php_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&guard.install_dir, &mariadb_install_dir);
    let latest = latest_builds_with_fallback(&guard.cache_path);
    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_set_active(
    state: tauri::State<'_, AppState>,
    line: String,
    version: String,
) -> Result<PhpCatalogResponse, String> {
    let mariadb_install_dir = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;
    let installed = guard.config.installed.get(&line).cloned().unwrap_or_default();
    if !installed.iter().any(|value| value == &version) {
        return Err(format!("version {version} is not installed for PHP {line}"));
    }
    guard.config.active.insert(line.clone(), version);
    set_php_current_link(&guard.install_dir, &line)?;
    guard.config.current_line = Some(line);
    save_php_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&guard.install_dir, &mariadb_install_dir);
    let latest = latest_builds_with_fallback(&guard.cache_path);
    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_set_ini_values(
    state: tauri::State<'_, AppState>,
    max_upload_size_mb: String,
    memory_limit_mb: String,
) -> Result<PhpCatalogResponse, String> {
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;

    let max_upload = normalize_mb_value(&max_upload_size_mb, false);
    if max_upload.is_empty() || !max_upload.chars().all(|c| c.is_ascii_digit()) {
        return Err("max upload size must be a positive integer in MB".to_string());
    }
    let memory = normalize_mb_value(&memory_limit_mb, true);
    let memory_ok = memory == "-1" || (!memory.is_empty() && memory.chars().all(|c| c.is_ascii_digit()));
    if !memory_ok {
        return Err("memory limit must be an integer in MB or -1".to_string());
    }

    guard.config.max_upload_size_mb = max_upload;
    guard.config.memory_limit_mb = memory;
    apply_php_ini_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    restart_php_fpm_services(&guard.install_dir, &guard.config)?;
    save_php_config(&guard.config_path, &guard.config)?;

    let latest = latest_builds_with_fallback(&guard.cache_path);
    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_set_current_line(state: tauri::State<'_, AppState>, line: String) -> Result<PhpCatalogResponse, String> {
    let mariadb_install_dir = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;

    let installed = guard.config.installed.get(&line).cloned().unwrap_or_default();
    if installed.is_empty() {
        return Err(format!("php line {line} is not installed"));
    }
    set_php_current_link(&guard.install_dir, &line)?;
    guard.config.current_line = Some(line);
    save_php_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&guard.install_dir, &mariadb_install_dir);
    let latest = latest_builds_with_fallback(&guard.cache_path);
    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn php_restart_fpm(state: tauri::State<'_, AppState>) -> Result<PhpCatalogResponse, String> {
    let mut guard = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?;
    ensure_php_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_php_installations(&install_dir, &mut guard.config)?;
    apply_php_ini_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    restart_php_fpm_services(&guard.install_dir, &guard.config)?;
    save_php_config(&guard.config_path, &guard.config)?;
    let latest = latest_builds_with_fallback(&guard.cache_path);
    Ok(PhpCatalogResponse {
        base_port: guard.config.base_port,
        max_upload_size_mb: guard.config.max_upload_size_mb.clone(),
        memory_limit_mb: guard.config.memory_limit_mb.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_php_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn mariadb_get_catalog(state: tauri::State<'_, AppState>) -> Result<MariaDbCatalogResponse, String> {
    let mut guard = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?;
    ensure_mariadb_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_mariadb_installations(&install_dir, &mut guard.config)?;
    apply_mariadb_config_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    save_mariadb_config(&guard.config_path, &guard.config)?;
    let latest = latest_mariadb_builds_with_fallback(&guard.cache_path);
    Ok(MariaDbCatalogResponse {
        port: guard.config.port,
        root_password: guard.config.root_password.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_mariadb_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn mariadb_set_config(
    state: tauri::State<'_, AppState>,
    port: u16,
    root_password: String,
) -> Result<MariaDbCatalogResponse, String> {
    if !(1024..=65000).contains(&port) {
        return Err("port must be between 1024 and 65000".to_string());
    }
    let mut guard = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?;
    ensure_mariadb_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_mariadb_installations(&install_dir, &mut guard.config)?;
    guard.config.port = port;
    guard.config.root_password = root_password;
    apply_mariadb_config_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    let _ = apply_mariadb_root_password_if_needed(&guard.install_dir, &guard.config, Some(&state.log_path));
    save_mariadb_config(&guard.config_path, &guard.config)?;
    let latest = latest_mariadb_builds_with_fallback(&guard.cache_path);
    Ok(MariaDbCatalogResponse {
        port: guard.config.port,
        root_password: guard.config.root_password.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_mariadb_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn mariadb_install_latest(
    state: tauri::State<'_, AppState>,
    line: String,
) -> Result<MariaDbCatalogResponse, String> {
    let php_install_dir = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?;
    ensure_mariadb_config_defaults(&mut guard.config);
    let latest = latest_mariadb_builds_with_fallback(&guard.cache_path);
    let build = latest
        .get(&line)
        .cloned()
        .ok_or_else(|| format!("could not find latest Windows x64 build for MariaDB {line}"))?;
    install_mariadb_line_build_with_progress(&guard.install_dir, &line, &build, |_| {})?;
    apply_mariadb_config_to_line(&guard.install_dir, &guard.template_dir, &line, &guard.config)?;
    guard
        .config
        .installed
        .insert(line.clone(), vec![build.version.clone()]);
    guard.config.current_line = Some(line);
    if let Some(current_line) = guard.config.current_line.clone() {
        set_mariadb_current_link(&guard.install_dir, &current_line)?;
    }
    save_mariadb_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&php_install_dir, &guard.install_dir);
    Ok(MariaDbCatalogResponse {
        port: guard.config.port,
        root_password: guard.config.root_password.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_mariadb_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn mariadb_uninstall_line(
    state: tauri::State<'_, AppState>,
    line: String,
) -> Result<MariaDbCatalogResponse, String> {
    let php_install_dir = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?;
    ensure_mariadb_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_mariadb_installations(&install_dir, &mut guard.config)?;

    if guard.config.current_line.as_deref() == Some(line.as_str()) {
        return Err(format!(
            "cannot uninstall current MariaDB line {line}; select another current line first"
        ));
    }
    if !guard.config.installed.contains_key(&line) {
        return Err(format!("mariadb line {line} is not installed"));
    }

    let line_dir = guard.install_dir.join(&line);
    let _ = stop_processes_by_exact_path(&line_dir.join("bin").join("mariadbd.exe"));
    if line_dir.exists() {
        fs::remove_dir_all(&line_dir)
            .map_err(|e| format!("failed to remove mariadb line directory '{}': {e}", line_dir.display()))?;
    }
    guard.config.installed.remove(&line);
    apply_mariadb_config_to_installed(&guard.install_dir, &guard.template_dir, &guard.config)?;
    save_mariadb_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&php_install_dir, &guard.install_dir);
    let latest = latest_mariadb_builds_with_fallback(&guard.cache_path);
    Ok(MariaDbCatalogResponse {
        port: guard.config.port,
        root_password: guard.config.root_password.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_mariadb_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn mariadb_set_current_line(
    state: tauri::State<'_, AppState>,
    line: String,
) -> Result<MariaDbCatalogResponse, String> {
    let php_install_dir = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?
        .install_dir
        .clone();
    let mut guard = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?;
    ensure_mariadb_config_defaults(&mut guard.config);
    let install_dir = guard.install_dir.clone();
    sync_local_mariadb_installations(&install_dir, &mut guard.config)?;
    let installed = guard.config.installed.get(&line).cloned().unwrap_or_default();
    if installed.is_empty() {
        return Err(format!("mariadb line {line} is not installed"));
    }
    guard.config.current_line = Some(line);
    if let Some(current_line) = guard.config.current_line.clone() {
        set_mariadb_current_link(&guard.install_dir, &current_line)?;
    }
    save_mariadb_config(&guard.config_path, &guard.config)?;
    let _ = refresh_user_path_with_runtime_currents(&php_install_dir, &guard.install_dir);
    let latest = latest_mariadb_builds_with_fallback(&guard.cache_path);
    Ok(MariaDbCatalogResponse {
        port: guard.config.port,
        root_password: guard.config.root_password.clone(),
        current_line: guard.config.current_line.clone(),
        runtimes: build_mariadb_catalog(&guard.config, &latest),
    })
}

#[tauri::command]
fn node_get_catalog() -> NodeCatalogResponse {
    build_node_catalog()
}

#[tauri::command]
fn node_install_major(major: String) -> Result<NodeCatalogResponse, String> {
    let catalog = build_node_catalog();
    if !catalog.nvm_available {
        return Err(catalog
            .error
            .unwrap_or_else(|| "nvm is not available on this system".to_string()));
    }
    let target = catalog
        .runtimes
        .iter()
        .find(|runtime| runtime.line == major)
        .and_then(|runtime| runtime.latest_version.clone())
        .ok_or_else(|| format!("no available Node version found for major {major}"))?;

    run_nvm_command(&["install", &target, "64"])?;
    Ok(build_node_catalog())
}

#[tauri::command]
fn node_set_current_version(state: tauri::State<'_, AppState>, version: String) -> Result<NodeCatalogResponse, String> {
    let catalog = build_node_catalog();
    if !catalog.nvm_available {
        return Err(catalog
            .error
            .unwrap_or_else(|| "nvm is not available on this system".to_string()));
    }
    if !catalog.installed_versions.iter().any(|v| v == &version) {
        return Err(format!("node version {version} is not installed"));
    }
    run_nvm_command(&["use", &version, "64"])?;
    let php_install_dir = state
        .php
        .lock()
        .map_err(|_| "failed to lock php state".to_string())?
        .install_dir
        .clone();
    let mariadb_install_dir = state
        .mariadb
        .lock()
        .map_err(|_| "failed to lock mariadb state".to_string())?
        .install_dir
        .clone();
    let _ = refresh_user_path_with_runtime_currents(&php_install_dir, &mariadb_install_dir);
    Ok(build_node_catalog())
}

#[tauri::command]
fn node_uninstall_version(version: String) -> Result<NodeCatalogResponse, String> {
    let catalog = build_node_catalog();
    if !catalog.nvm_available {
        return Err(catalog
            .error
            .unwrap_or_else(|| "nvm is not available on this system".to_string()));
    }
    if !catalog.installed_versions.iter().any(|v| v == &version) {
        return Err(format!("node version {version} is not installed"));
    }
    if catalog.current_version.as_deref() == Some(version.as_str()) {
        return Err(format!("cannot uninstall current Node version {version}; select another current first"));
    }
    run_nvm_command(&["uninstall", &version])?;
    Ok(build_node_catalog())
}

fn node_current_version_light() -> Option<String> {
    let output = run_nvm_command(&["current"]).ok()?;
    extract_versions_from_text(&output).into_iter().next()
}

#[tauri::command]
fn get_service_statuses(state: tauri::State<'_, AppState>) -> Result<Vec<ServiceStatusItem>, String> {
    let (php_install_dir, php_current_line, php_base_port) = {
        let guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        (
            guard.install_dir.clone(),
            guard.config.current_line.clone(),
            guard.config.base_port,
        )
    };
    let (mariadb_install_dir, mariadb_current_line, mariadb_port) = {
        let guard = state
            .mariadb
            .lock()
            .map_err(|_| "failed to lock mariadb state".to_string())?;
        (
            guard.install_dir.clone(),
            guard.config.current_line.clone(),
            guard.config.port,
        )
    };

    let php_version = php_current_line
        .as_ref()
        .and_then(|_| detect_php_version_from_binary(&php_install_dir.join("current")))
        .unwrap_or_else(|| "-".to_string());
    let php_running = php_current_line
        .as_ref()
        .map(|line| is_php_cgi_listening_in_root(&php_install_dir, line_port(php_base_port, line)))
        .unwrap_or(false);
    let php_port = php_current_line
        .as_ref()
        .map(|line| line_port(php_base_port, line).to_string())
        .unwrap_or_else(|| "-".to_string());

    let node_version = node_current_version_light().unwrap_or_else(|| "-".to_string());
    let node_ready = node_version != "-";

    let mariadb_version = mariadb_current_line
        .as_ref()
        .and_then(|_| detect_mariadb_version_from_binary(&mariadb_install_dir.join("current")))
        .unwrap_or_else(|| "-".to_string());
    let mariadb_running = is_mariadb_listening_in_root(&mariadb_install_dir, mariadb_port);

    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    let nginx_root = bin_root.join("nginx");
    let nginx_version = detect_nginx_version_from_binary(&nginx_root).unwrap_or_else(|| "-".to_string());
    let nginx_running = is_process_running("nginx.exe");

    Ok(vec![
        ServiceStatusItem {
            key: "php".to_string(),
            label: "PHP".to_string(),
            status: if php_running { "running" } else { "stopped" }.to_string(),
            healthy: php_running,
            version: php_version,
            port: php_port,
        },
        ServiceStatusItem {
            key: "node".to_string(),
            label: "Node".to_string(),
            status: if node_ready { "ready" } else { "stopped" }.to_string(),
            healthy: node_ready,
            version: node_version,
            port: "-".to_string(),
        },
        ServiceStatusItem {
            key: "mysql".to_string(),
            label: "MySQL".to_string(),
            status: if mariadb_running { "running" } else { "stopped" }.to_string(),
            healthy: mariadb_running,
            version: mariadb_version,
            port: mariadb_port.to_string(),
        },
        ServiceStatusItem {
            key: "nginx".to_string(),
            label: "Nginx".to_string(),
            status: if nginx_running { "running" } else { "stopped" }.to_string(),
            healthy: nginx_running,
            version: nginx_version,
            port: "80 / 443".to_string(),
        },
    ])
}

#[tauri::command]
fn services_start_all(state: tauri::State<'_, AppState>) -> Result<Vec<ServiceStatusItem>, String> {
    let log_path = state.log_path.clone();
    append_runtime_log(&log_path, "INFO", "services.start_all", "Start all requested");
    let (php_install_dir, php_config) = {
        let guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        (guard.install_dir.clone(), guard.config.clone())
    };
    let (mariadb_install_dir, mariadb_config) = {
        let guard = state
            .mariadb
            .lock()
            .map_err(|_| "failed to lock mariadb state".to_string())?;
        (guard.install_dir.clone(), guard.config.clone())
    };

    let mut errors: Vec<String> = Vec::new();
    if let Err(error) = restart_php_fpm_services(&php_install_dir, &php_config) {
        append_runtime_log(&log_path, "ERROR", "services.start_all.php", &error);
        errors.push(format!("php: {error}"));
    } else {
        append_runtime_log(&log_path, "INFO", "services.start_all.php", "PHP-FPM started/restarted");
    }
    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    if let Err(error) = start_nginx_if_needed(&bin_root.join("nginx")) {
        append_runtime_log(&log_path, "ERROR", "services.start_all.nginx", &error);
        errors.push(format!("nginx: {error}"));
    } else {
        append_runtime_log(&log_path, "INFO", "services.start_all.nginx", "Nginx started/verified");
    }
    if let Err(error) = initialize_and_start_mariadb_if_needed(&mariadb_install_dir, &mariadb_config, Some(&log_path)) {
        append_runtime_log(&log_path, "ERROR", "services.start_all.mysql", &error);
        errors.push(format!("mysql: {error}"));
    } else {
        append_runtime_log(&log_path, "INFO", "services.start_all.mysql", "MariaDB started/verified");
    }
    if let Err(error) = apply_mariadb_root_password_if_needed(&mariadb_install_dir, &mariadb_config, Some(&log_path)) {
        append_runtime_log(&log_path, "ERROR", "services.start_all.mysql_password", &error);
        errors.push(format!("mysql-password: {error}"));
    } else if !mariadb_config.root_password.trim().is_empty() {
        append_runtime_log(&log_path, "INFO", "services.start_all.mysql_password", "MariaDB root password applied/validated");
    }

    if !errors.is_empty() {
        append_runtime_log(&log_path, "ERROR", "services.start_all", &errors.join(" | "));
        return Err(errors.join(" | "));
    }
    let _ = refresh_user_path_with_runtime_currents(&php_install_dir, &mariadb_install_dir);
    append_runtime_log(&log_path, "INFO", "services.start_all", "Start all completed successfully");
    get_service_statuses(state)
}

#[tauri::command]
fn services_stop_all(state: tauri::State<'_, AppState>) -> Result<Vec<ServiceStatusItem>, String> {
    let log_path = state.log_path.clone();
    append_runtime_log(&log_path, "INFO", "services.stop_all", "Stop all requested");
    let (php_install_dir, mariadb_install_dir, mariadb_config) = {
        let php_guard = state
            .php
            .lock()
            .map_err(|_| "failed to lock php state".to_string())?;
        let mariadb_guard = state
            .mariadb
            .lock()
            .map_err(|_| "failed to lock mariadb state".to_string())?;
        (
            php_guard.install_dir.clone(),
            mariadb_guard.install_dir.clone(),
            mariadb_guard.config.clone(),
        )
    };

    let mut errors: Vec<String> = Vec::new();
    if let Err(error) = stop_php_fpm_services(&php_install_dir) {
        append_runtime_log(&log_path, "ERROR", "services.stop_all.php", &error);
        errors.push(format!("php: {error}"));
    } else {
        append_runtime_log(&log_path, "INFO", "services.stop_all.php", "PHP-FPM stopped");
    }

    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    if let Err(error) = stop_nginx_if_running(&bin_root.join("nginx")) {
        append_runtime_log(&log_path, "ERROR", "services.stop_all.nginx", &error);
        errors.push(format!("nginx: {error}"));
    } else {
        append_runtime_log(&log_path, "INFO", "services.stop_all.nginx", "Nginx stopped");
    }

    if let Err(error) = stop_mariadb_if_running(&mariadb_install_dir, &mariadb_config) {
        append_runtime_log(&log_path, "ERROR", "services.stop_all.mysql", &error);
        errors.push(format!("mysql: {error}"));
    } else {
        append_runtime_log(&log_path, "INFO", "services.stop_all.mysql", "MariaDB stopped");
    }

    if !errors.is_empty() {
        append_runtime_log(&log_path, "ERROR", "services.stop_all", &errors.join(" | "));
        return Err(errors.join(" | "));
    }
    append_runtime_log(&log_path, "INFO", "services.stop_all", "Stop all completed successfully");
    get_service_statuses(state)
}

fn emit_bootstrap_progress(app: &tauri::AppHandle, payload: BootstrapProgressEvent) {
    let _ = app.emit("bootstrap-progress", payload);
}

fn bootstrap_php_and_composer(app: tauri::AppHandle) {
    emit_bootstrap_progress(
        &app,
        BootstrapProgressEvent {
            phase: "php".to_string(),
            status: "started".to_string(),
            percent: Some(0.0),
            message: "Checking latest PHP release...".to_string(),
        },
    );

    let (cache_path, install_dir, config_path, template_dir) = {
        let state = app.state::<AppState>();
        let guard = match state.php.lock() {
            Ok(guard) => guard,
            Err(_) => {
                emit_bootstrap_progress(
                    &app,
                    BootstrapProgressEvent {
                        phase: "php".to_string(),
                        status: "error".to_string(),
                        percent: None,
                        message: "Failed to lock PHP state".to_string(),
                    },
                );
                return;
            }
        };
        (
            guard.cache_path.clone(),
            guard.install_dir.clone(),
            guard.config_path.clone(),
            guard.template_dir.clone(),
        )
    };

    let latest = latest_builds_with_fallback(&cache_path);
    let Some((_line, build)) = latest
        .iter()
        .max_by(|a, b| compare_versions(&a.1.version, &b.1.version))
        .map(|(k, v)| (k.clone(), v.clone()))
    else {
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "php".to_string(),
                status: "error".to_string(),
                percent: None,
                message: "No PHP releases found.".to_string(),
            },
        );
        return;
    };

    let target_line = build.line.clone();
    let target_version = build.version.clone();
    let already_installed = detect_php_version_from_binary(&install_dir.join(&target_line))
        .map(|v| v == target_version)
        .unwrap_or(false);

    if already_installed {
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "php".to_string(),
                status: "skipped".to_string(),
                percent: Some(100.0),
                message: format!("Latest PHP {} already installed.", target_version),
            },
        );
    } else {
        let install_result = install_php_line_build_with_progress(&install_dir, &target_line, &build, |pct| {
            emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "php".to_string(),
                    status: "progress".to_string(),
                    percent: Some(pct),
                    message: format!("Downloading PHP {}...", target_version),
                },
            );
        });
        if let Err(error) = install_result {
            emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "php".to_string(),
                    status: "error".to_string(),
                    percent: None,
                    message: error,
                },
            );
            return;
        }
    }

    {
        let state = app.state::<AppState>();
        let mut guard = match state.php.lock() {
            Ok(guard) => guard,
            Err(_) => {
                emit_bootstrap_progress(
                    &app,
                    BootstrapProgressEvent {
                        phase: "php".to_string(),
                        status: "error".to_string(),
                        percent: None,
                        message: "Failed to lock PHP state after install".to_string(),
                    },
                );
                return;
            }
        };
        ensure_php_config_defaults(&mut guard.config);
        let detected_version =
            detect_php_version_from_binary(&install_dir.join(&target_line)).unwrap_or(target_version.clone());
        guard
            .config
            .installed
            .insert(target_line.clone(), vec![detected_version.clone()]);
        guard.config.active.insert(target_line.clone(), detected_version);
        guard.config.current_line = Some(target_line.clone());
        if let Err(error) = apply_php_ini_to_line(&install_dir, &template_dir, &target_line, &guard.config)
            .and_then(|_| set_php_current_link(&install_dir, &target_line))
            .and_then(|_| restart_php_fpm_services(&install_dir, &guard.config))
            .and_then(|_| save_php_config(&config_path, &guard.config))
        {
            emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "php".to_string(),
                    status: "error".to_string(),
                    percent: None,
                    message: error,
                },
            );
            return;
        }
    }

    emit_bootstrap_progress(
        &app,
        BootstrapProgressEvent {
            phase: "php".to_string(),
            status: "completed".to_string(),
            percent: Some(100.0),
            message: format!("PHP {} ready.", target_version),
        },
    );

    emit_bootstrap_progress(
        &app,
        BootstrapProgressEvent {
            phase: "composer".to_string(),
            status: "started".to_string(),
            percent: None,
            message: "Downloading Composer in background...".to_string(),
        },
    );

    let bin_root = install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| install_dir.clone());
    let composer_dir = bin_root.join("composer");
    let composer_phar = composer_dir.join("composer.phar");
    let legacy_composer_bat = composer_dir.join("composer.bat");
    let composer_url = "https://getcomposer.org/download/latest-stable/composer.phar";
    if composer_phar.exists() {
        if legacy_composer_bat.exists() {
            let _ = fs::remove_file(&legacy_composer_bat);
        }
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "composer".to_string(),
                status: "skipped".to_string(),
                percent: Some(100.0),
                message: "Composer already exists.".to_string(),
            },
        );
    } else {
        let downloads_dir = shared_downloads_dir(&bin_root);
        let _ = fs::create_dir_all(&downloads_dir);
        let composer_tmp = downloads_dir.join("composer.phar");
        if composer_tmp.exists() {
            let _ = fs::remove_file(&composer_tmp);
        }
        let composer_result = download_with_progress(composer_url, &composer_tmp, |_| {});
        match composer_result {
            Ok(_) => {
                if let Some(parent) = composer_phar.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if composer_phar.exists() {
                    let _ = fs::remove_file(&composer_phar);
                }
                if let Err(error) = fs::rename(&composer_tmp, &composer_phar) {
                    emit_bootstrap_progress(
                        &app,
                        BootstrapProgressEvent {
                            phase: "composer".to_string(),
                            status: "error".to_string(),
                            percent: None,
                            message: format!("Composer downloaded but move failed: {error}"),
                        },
                    );
                    return;
                }
                if legacy_composer_bat.exists() {
                    let _ = fs::remove_file(&legacy_composer_bat);
                }
            emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "composer".to_string(),
                    status: "completed".to_string(),
                    percent: Some(100.0),
                    message: "Composer downloaded.".to_string(),
                },
            )
            }
            Err(error) => emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "composer".to_string(),
                    status: "error".to_string(),
                    percent: None,
                    message: error,
                },
            ),
        }
    }

    emit_bootstrap_progress(
        &app,
        BootstrapProgressEvent {
            phase: "nvm".to_string(),
            status: "started".to_string(),
            percent: None,
            message: "Checking nvm-windows...".to_string(),
        },
    );

    if nvm_is_available() {
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "nvm".to_string(),
                status: "skipped".to_string(),
                percent: Some(100.0),
                message: "nvm-windows is already installed.".to_string(),
            },
        );
    } else {
        let install_result = install_nvm_windows_silently(&bin_root);
        match install_result {
            Ok(version) => emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "nvm".to_string(),
                    status: "completed".to_string(),
                    percent: Some(100.0),
                    message: format!("nvm-windows installed ({version})."),
                },
            ),
            Err(error) => emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "nvm".to_string(),
                    status: "error".to_string(),
                    percent: None,
                    message: format!("Failed to install nvm-windows: {error}"),
                },
            ),
        }
    }

    let nginx_root = bin_root.join("nginx");
    if detect_nginx_version_from_binary(&nginx_root).is_some() {
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "nginx".to_string(),
                status: "skipped".to_string(),
                percent: Some(100.0),
                message: "nginx already exists.".to_string(),
            },
        );
    } else {
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "nginx".to_string(),
                status: "started".to_string(),
                percent: Some(0.0),
                message: "Downloading latest nginx in background...".to_string(),
            },
        );
        let nginx_result = install_latest_nginx_with_progress(&bin_root, |pct| {
            emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "nginx".to_string(),
                    status: "progress".to_string(),
                    percent: Some(pct),
                    message: "Downloading latest nginx in background...".to_string(),
                },
            );
        });
        match nginx_result {
            Ok(version) => emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "nginx".to_string(),
                    status: "completed".to_string(),
                    percent: Some(100.0),
                    message: format!("nginx {version} ready."),
                },
            ),
            Err(error) => emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "nginx".to_string(),
                    status: "error".to_string(),
                    percent: None,
                    message: format!("Failed to download nginx: {error}"),
                },
            ),
        }
    }

    let auto_start_enabled = app
        .state::<AppState>()
        .settings
        .lock()
        .ok()
        .map(|guard| guard.config.auto_start_services)
        .unwrap_or(true);
    if !auto_start_enabled {
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "services".to_string(),
                status: "skipped".to_string(),
                percent: Some(100.0),
                message: "Auto-start disabled in Settings.".to_string(),
            },
        );
        let _ = refresh_user_path_with_runtime_currents(&install_dir, &bin_root.join("mariadb"));
        return;
    }

    emit_bootstrap_progress(
        &app,
        BootstrapProgressEvent {
            phase: "services".to_string(),
            status: "started".to_string(),
            percent: None,
            message: "Starting nginx and MariaDB...".to_string(),
        },
    );

    let state = app.state::<AppState>();
    let log_path = state.log_path.clone();

    let (mariadb_install_dir, mariadb_config) = match state.mariadb.lock() {
        Ok(guard) => (guard.install_dir.clone(), guard.config.clone()),
        Err(_) => {
            emit_bootstrap_progress(
                &app,
                BootstrapProgressEvent {
                    phase: "services".to_string(),
                    status: "error".to_string(),
                    percent: None,
                    message: "Failed to lock MariaDB state for auto-start.".to_string(),
                },
            );
            return;
        }
    };

    if let Err(error) = initialize_and_start_mariadb_if_needed(&mariadb_install_dir, &mariadb_config, Some(&log_path))
    {
        append_runtime_log(&log_path, "ERROR", "bootstrap.services.mariadb", &error);
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "services".to_string(),
                status: "error".to_string(),
                percent: None,
                message: format!("MariaDB auto-start failed: {error}"),
            },
        );
    }

    let nginx_root = mariadb_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| mariadb_install_dir.clone())
        .join("nginx");
    if let Err(error) = start_nginx_if_needed(&nginx_root) {
        append_runtime_log(&log_path, "ERROR", "bootstrap.services.nginx", &error);
        emit_bootstrap_progress(
            &app,
            BootstrapProgressEvent {
                phase: "services".to_string(),
                status: "error".to_string(),
                percent: None,
                message: format!("Nginx auto-start failed: {error}"),
            },
        );
    }

    emit_bootstrap_progress(
        &app,
        BootstrapProgressEvent {
            phase: "services".to_string(),
            status: "completed".to_string(),
            percent: Some(100.0),
            message: "Auto-start completed.".to_string(),
        },
    );
    let _ = refresh_user_path_with_runtime_currents(&install_dir, &mariadb_install_dir);
}

fn refresh_runtime_catalogs_hourly(app: tauri::AppHandle) {
    loop {
        let (php_cache_path, mariadb_cache_path, log_path, auto_update_enabled) = {
            let state = app.state::<AppState>();
            let php_cache_path = state
                .php
                .lock()
                .ok()
                .map(|guard| guard.cache_path.clone());
            let mariadb_cache_path = state
                .mariadb
                .lock()
                .ok()
                .map(|guard| guard.cache_path.clone());
            let auto_update_enabled = state
                .settings
                .lock()
                .ok()
                .map(|guard| guard.config.auto_update)
                .unwrap_or(true);
            (php_cache_path, mariadb_cache_path, state.log_path.clone(), auto_update_enabled)
        };
        if !auto_update_enabled {
            std::thread::sleep(std::time::Duration::from_secs(60));
            continue;
        }
        let logs_dir = log_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let state_path = logs_dir.join("_updates_state.txt");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last_checked = fs::read_to_string(&state_path)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let elapsed = now.saturating_sub(last_checked);
        if last_checked > 0 && elapsed < RUNTIME_UPDATE_CHECK_INTERVAL_SECONDS {
            let remaining = RUNTIME_UPDATE_CHECK_INTERVAL_SECONDS.saturating_sub(elapsed);
            std::thread::sleep(std::time::Duration::from_secs(remaining.min(60)));
            continue;
        }

        let php_ok = php_cache_path
            .as_ref()
            .map(|path| fetch_php_releases_json_with_cache(path).is_ok())
            .unwrap_or(false);
        let mariadb_ok = mariadb_cache_path
            .as_ref()
            .map(|path| fetch_mariadb_builds_with_cache(path).is_ok())
            .unwrap_or(false);
        let node_catalog = node_get_catalog();
        let node_ok = node_catalog.nvm_available && node_catalog.error.is_none();

        append_runtime_log(
            &log_path,
            "INFO",
            "updates.hourly",
            &format!(
                "Hourly update check finished (php={}, mariadb={}, node={})",
                php_ok, mariadb_ok, node_ok
            ),
        );
        let _ = fs::write(&state_path, now.to_string());

        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[tauri::command]
fn settings_get(state: tauri::State<'_, AppState>) -> Result<AppSettingsResponse, String> {
    let guard = state
        .settings
        .lock()
        .map_err(|_| "failed to lock settings state".to_string())?;
    Ok(app_settings_response(&guard.path, &guard.config))
}

#[tauri::command]
fn settings_set(
    state: tauri::State<'_, AppState>,
    auto_start_services: bool,
    auto_update: bool,
) -> Result<AppSettingsResponse, String> {
    let mut guard = state
        .settings
        .lock()
        .map_err(|_| "failed to lock settings state".to_string())?;
    guard.config.auto_start_services = auto_start_services;
    guard.config.auto_update = auto_update;
    save_app_settings(&guard.path, &guard.config)?;
    append_runtime_log(
        &state.log_path,
        "INFO",
        "settings",
        &format!("Updated settings: autoStartServices={}, autoUpdate={}", auto_start_services, auto_update),
    );
    Ok(app_settings_response(&guard.path, &guard.config))
}

fn stop_services_on_shutdown(app: &tauri::AppHandle) {
    if SHUTDOWN_STOP_TRIGGERED.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = app.state::<AppState>();
    let log_path = state.log_path.clone();

    append_runtime_log(&log_path, "INFO", "shutdown", "Stopping services before app exit...");

    let (php_install_dir, mariadb_install_dir, mariadb_config) = {
        let php_guard = match state.php.lock() {
            Ok(value) => value,
            Err(_) => {
                append_runtime_log(&log_path, "ERROR", "shutdown", "Failed to lock PHP state");
                return;
            }
        };
        let mariadb_guard = match state.mariadb.lock() {
            Ok(value) => value,
            Err(_) => {
                append_runtime_log(&log_path, "ERROR", "shutdown", "Failed to lock MariaDB state");
                return;
            }
        };
        (
            php_guard.install_dir.clone(),
            mariadb_guard.install_dir.clone(),
            mariadb_guard.config.clone(),
        )
    };

    if let Err(error) = stop_php_fpm_services(&php_install_dir) {
        append_runtime_log(&log_path, "ERROR", "shutdown.php", &error);
    } else {
        append_runtime_log(&log_path, "INFO", "shutdown.php", "PHP-FPM stopped");
    }

    let bin_root = php_install_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| php_install_dir.clone());
    if let Err(error) = stop_nginx_if_running(&bin_root.join("nginx")) {
        append_runtime_log(&log_path, "ERROR", "shutdown.nginx", &error);
    } else {
        append_runtime_log(&log_path, "INFO", "shutdown.nginx", "Nginx stopped");
    }

    if let Err(error) = stop_mariadb_if_running(&mariadb_install_dir, &mariadb_config) {
        append_runtime_log(&log_path, "ERROR", "shutdown.mysql", &error);
    } else {
        append_runtime_log(&log_path, "INFO", "shutdown.mysql", "MariaDB stopped");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("failed to resolve app data dir: {e}"))?;
            fs::create_dir_all(&data_dir).map_err(|e| format!("failed to create app data dir: {e}"))?;

            let runtime_store_path = data_dir.join("runtimes.json");
            let store = load_store(&runtime_store_path);
            save_store(&runtime_store_path, &store)?;
            let app_settings_path = envloom_global_config_path();
            let mut app_settings = load_app_settings(&app_settings_path);
            ensure_app_settings_defaults(&mut app_settings);
            save_app_settings(&app_settings_path, &app_settings)?;
            let sites_store_path = data_dir.join("sites.json");
            let sites_store = load_sites_store(&sites_store_path);
            save_sites_store(&sites_store_path, &sites_store)?;

            let bin_root = if cfg!(debug_assertions) {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bin")
            } else {
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(Path::to_path_buf))
                    .unwrap_or_else(|| data_dir.clone())
                    .join("bin")
            };
            let logs_dir = resolve_logs_dir_from_bin_root(&bin_root);
            fs::create_dir_all(&logs_dir).map_err(|e| format!("failed to create logs dir: {e}"))?;
            let log_path = logs_dir.join("runtime.log");
            let php_install_dir = bin_root.join("php");
            fs::create_dir_all(&php_install_dir).map_err(|e| format!("failed to create php bin directory: {e}"))?;
            let mariadb_install_dir = bin_root.join("mariadb");
            fs::create_dir_all(&mariadb_install_dir)
                .map_err(|e| format!("failed to create mariadb bin directory: {e}"))?;
            let template_dir = if cfg!(debug_assertions) {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config")
            } else {
                data_dir.join("config")
            };
            ensure_php_template_files(&template_dir)?;
            let sites_dir = if cfg!(debug_assertions) {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sites")
            } else {
                bin_root
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| bin_root.clone())
                    .join("sites")
            };
            let current_domains: Vec<String> = sites_store.sites.iter().map(|site| site.domain.clone()).collect();
            let _ = reconcile_nginx_site_configs(&sites_dir, &current_domains);

            let php_config_path = php_install_dir.join("_state.json");
            let php_cache_path = php_install_dir.join("_releases_cache.json");
            let mut php_config = load_php_config(&php_config_path);
            ensure_php_config_defaults(&mut php_config);
            sync_local_php_installations(&php_install_dir, &mut php_config)?;
            apply_php_ini_to_installed(&php_install_dir, &template_dir, &php_config)?;
            if let Some(current_line) = php_config.current_line.clone() {
                let _ = set_php_current_link(&php_install_dir, &current_line);
            }
            let _ = restart_php_fpm_services(&php_install_dir, &php_config);
            save_php_config(&php_config_path, &php_config)?;

            let mariadb_config_path = mariadb_install_dir.join("_state.json");
            let mariadb_cache_path = mariadb_install_dir.join("_releases_cache.json");
            let mut mariadb_config = load_mariadb_config(&mariadb_config_path);
            ensure_mariadb_config_defaults(&mut mariadb_config);
            sync_local_mariadb_installations(&mariadb_install_dir, &mut mariadb_config)?;
            apply_mariadb_config_to_installed(&mariadb_install_dir, &template_dir, &mariadb_config)?;
            if let Some(current_line) = mariadb_config.current_line.clone() {
                let _ = set_mariadb_current_link(&mariadb_install_dir, &current_line);
            }
            save_mariadb_config(&mariadb_config_path, &mariadb_config)?;

            app.manage(AppState {
                runtimes: Mutex::new(RuntimeState {
                    path: runtime_store_path,
                    store,
                }),
                sites: Mutex::new(SiteState {
                    path: sites_store_path,
                    store: sites_store,
                }),
                php: Mutex::new(PhpState {
                    config_path: php_config_path,
                    cache_path: php_cache_path,
                    install_dir: php_install_dir,
                    template_dir,
                    config: php_config,
                }),
                mariadb: Mutex::new(MariaDbState {
                    config_path: mariadb_config_path,
                    cache_path: mariadb_cache_path,
                    install_dir: mariadb_install_dir,
                    template_dir: if cfg!(debug_assertions) {
                        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config")
                    } else {
                        data_dir.join("config")
                    },
                    config: mariadb_config,
                }),
                settings: Mutex::new(AppSettingsState {
                    path: app_settings_path,
                    config: app_settings,
                }),
                log_path,
            });
            let app_handle = app.handle().clone();
            std::thread::spawn(move || bootstrap_php_and_composer(app_handle));
            let update_handle = app.handle().clone();
            std::thread::spawn(move || refresh_runtime_catalogs_hourly(update_handle));
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            list_runtimes,
            set_active_runtime,
            add_runtime_version,
            remove_runtime_version,
            list_sites,
            site_pick_existing_folder,
            site_inspect_path,
            create_site,
            delete_site,
            site_regenerate_ssl,
            site_set_ssl,
            site_set_php_version,
            logs_tail,
            logs_list_files,
            logs_read_file,
            php_get_catalog,
            php_set_base_port,
            php_install_latest,
            php_uninstall_line,
            php_set_active,
            php_set_ini_values,
            php_set_current_line,
            php_restart_fpm,
            mariadb_get_catalog,
            mariadb_set_config,
            mariadb_install_latest,
            mariadb_uninstall_line,
            mariadb_set_current_line,
            get_service_statuses,
            services_start_all,
            services_stop_all,
            settings_get,
            settings_set,
            node_get_catalog,
            node_install_major,
            node_set_current_version,
            node_uninstall_version
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application");

    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
            stop_services_on_shutdown(app_handle);
        }
        _ => {}
    });
}
