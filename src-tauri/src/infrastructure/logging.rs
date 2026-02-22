use chrono::Local;
use std::fs;
use std::io::Write;
use std::path::Path;

pub(crate) fn append_runtime_log(log_path: &Path, level: &str, scope: &str, message: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let line = format!("[{ts}] [{level}] [{scope}] {message}\n");
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}
