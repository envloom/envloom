# Envloom

Envloom is a local development stack manager for Windows, inspired by tools like Laragon and Herd.

It aims to make local web development simple while still being flexible:

- PHP (multiple versions)
- Nginx
- MariaDB
- Node (via `nvm-windows`)
- Per-site runtime selection and local SSL
- Centralized logs and service controls

## Status

Alpha / active development.

The project is functional for local runtime management and site provisioning, but it is still evolving quickly.

## Tech Stack

- Tauri (Rust backend)
- React + TypeScript
- Vite
- Tailwind CSS v4
- shadcn/ui

## Current Features

- Runtime management for PHP, Node, MariaDB, and Nginx
- Runtime `current` selection with local shims in `bin`
- PHP `php.ini` management (base + version overrides)
- MariaDB install/current selection/root password handling
- Site creation and linking (Laravel and existing PHP projects)
- Local SSL certificate generation per site
- Nginx vhost generation per site
- Hosts file block management (with elevation helper)
- Dashboard service status cards
- Logs page (Runtime / PHP / Nginx / MariaDB)
- Global settings (`autoStartServices`, `autoUpdate`)

For a more detailed checklist, see [`FEATURES.md`](./FEATURES.md).

## Project Structure

- `src/` - frontend (React UI)
- `src-tauri/` - backend (Rust/Tauri)
- `src-tauri/config/` - runtime config templates

In development mode, runtime binaries and generated files are stored under:

- `src-tauri/bin/`
- `src-tauri/logs/`
- `src-tauri/sites/`

These are ignored in Git.

## Development (Windows)

### Prerequisites

- Node.js (recommended: latest LTS)
- `pnpm`
- Rust toolchain
- Visual Studio Build Tools (for Rust/Tauri on Windows)

### Run

```bash
pnpm install
pnpm tauri dev
```

### Build

```bash
pnpm tauri build
```

## Releases

GitHub Actions includes:

- `CI` (checks and builds on PRs/pushes)
- `Release` (Windows Tauri build on tags `v*`)

### Test the release workflow first (recommended)

Use a prerelease tag (tags containing `-` are marked as prerelease automatically):

```bash
git tag v0.1.0-beta.1
git push origin v0.1.0-beta.1
```

This creates a draft GitHub Release with Windows build artifacts.

### Stable release

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Notes

- Envloom manages local binaries and services, so some actions may require Administrator permissions (for example, editing the Windows hosts file).
- The app includes a helper script for UAC elevation when updating hosts.

## Roadmap (short-term)

- Settings page expansion
- Service controls page
- More robust site provisioning templates
- Better diagnostics and log tooling
- Systray integration

## License

MIT
