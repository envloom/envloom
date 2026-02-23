<p align="center">
  <img src="./public/logo.png" alt="Envloom" width="220" />
</p>

# Envloom

Envloom is a local development stack manager focused on a simple workflow with versioned runtimes and per-site configuration.

## Features

- Versioned runtime management for:
  - PHP
  - Node (via NVM)
  - MariaDB
  - Nginx
- Runtime `current` selection with local shims in `bin`
- PHP runtime configuration:
  - `php.ini` managed values
  - version-specific overrides
  - FPM port mapping by PHP line
- MariaDB runtime configuration:
  - version install/current selection
  - root password handling
  - local config generation
- Site management:
  - create new Laravel sites
  - link existing projects
  - per-site PHP version selection
  - local SSL on/off
- Networking automation:
  - Nginx vhost generation per site
  - hosts file block management (with elevation helper)
  - local CA + per-site certificates
- Service controls:
  - start/stop all
  - service status in dashboard
  - auto-start on app launch (configurable)
  - auto-stop on app exit
- Logs and diagnostics:
  - centralized runtime logs
  - PHP / MariaDB / Nginx logs
  - in-app log viewer
- Global settings:
  - `autoStartServices`
  - `autoUpdate`

For the detailed implementation checklist, see [`FEATURES.md`](./FEATURES.md).

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Make focused changes
4. Run checks locally (`pnpm -s exec tsc --noEmit` and `cargo check` in `src-tauri`)
5. Open a pull request with a clear description

Please keep changes scoped and avoid committing generated runtime binaries/logs.
