<p align="center">
  <img src="./public/logo.svg" alt="Envloom" width="220" />
</p>

# Envloom

Envloom is a local development stack manager for Windows with versioned runtimes, per-site config, local SSL, and a desktop-first workflow.

## Features

- Runtime manager for PHP, Node (NVM), MariaDB and Nginx
- Install multiple versions and choose a `current` version per runtime
- Local shims in `bin` (`php`, `php85`, `mysql`, `nginx`, `composer`, `loom`)
- PHP FPM port mapping by PHP line + managed `php.ini`
- MariaDB runtime install/current selection + root password config
- Sites management:
  - link existing projects
  - create Laravel sites
  - per-site PHP version
  - local SSL on/off
- Local networking automation:
  - Nginx site configs
  - local CA + per-site certificates
  - hosts block sync (with elevation helper)
- Dashboard service status + `Start all` / `Stop all`
- Systray with quick actions, runtime switching, site links, configs and logs shortcuts
- Centralized logs (`runtime`, PHP, MariaDB, Nginx) + in-app log viewer
- Settings:
  - auto-start services
  - auto-check updates
  - start with Windows
  - start minimized
- CLI (`loom`) for local project linking and runtime switching

For the detailed implementation checklist, see [`FEATURES.md`](./FEATURES.md).

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Make focused changes
4. Run checks locally (`pnpm -s exec tsc --noEmit` and `cargo check` in `src-tauri`)
5. Open a pull request with a clear description

Please keep changes scoped and avoid committing generated runtime binaries/logs.
