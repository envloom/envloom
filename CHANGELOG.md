# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Envloom branding (Tauri app, UI, settings path, hosts block markers)
- Runtime managers for PHP, Node, MariaDB, and Nginx
- Sites management (create/link, SSL, nginx vhosts, hosts block handling)
- Logs page with Runtime/PHP/Nginx/MariaDB viewers
- Global settings (`autoStartServices`, `autoUpdate`) persisted in `~/.envloom/config.json`
- Additional global settings: `startWithWindows` and `startMinimized`
- GitHub Actions CI and Windows release workflows
- Systray quick menu with dynamic submenus for sites and runtimes
- CLI mode in the main executable (`--cli`) with `loom.cmd` shim
- CLI commands: `current`, `list`, `link`, `unlink`, `ssl`, `php`, `node`

### Changed

- Sidebar now uses `public/logo.png`
- Runtime shims are generated in `bin/` and PATH is managed via a single `bin` entry
- PATH management also includes the app executable directory (for CLI shim resolution)
- Centralized logs under `logs/`
- Windows startup entry can launch Envloom minimized (`--minimized`)

### Fixed

- MariaDB stop logic now verifies shutdown and kills by runtime root fallback
- CI workflow `pnpm` setup order
- `.gitignore` rule that accidentally ignored `src/features/logs`
- `loom.cmd` shim resolution for dev/build executable locations
