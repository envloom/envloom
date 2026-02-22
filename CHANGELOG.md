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
- GitHub Actions CI and Windows release workflows

### Changed

- Sidebar now uses `public/logo.png`
- Runtime shims are generated in `bin/` and PATH is managed via a single `bin` entry
- Centralized logs under `logs/`

### Fixed

- MariaDB stop logic now verifies shutdown and kills by runtime root fallback
- CI workflow `pnpm` setup order
- `.gitignore` rule that accidentally ignored `src/features/logs`

