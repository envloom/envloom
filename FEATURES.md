# Envloom Features Checklist

## Estado actual
- [x] UI base tipo dashboard para Envloom.
- [x] Tailwind CSS v4 integrado en Vite.
- [x] shadcn/ui instalado y funcionando.
- [x] Sidebar con rutas reales para Dashboard, PHP, Node y MariaDB.
- [x] Sidebar actualizado con menu `Sites` (reemplaza `Projects`).
- [x] Ventana Tauri centrada, no redimensionable y sin maximizar.
- [x] Watcher de Tauri estabilizado ignorando `src-tauri/bin` y `src-tauri/config` en dev (`src-tauri/.taurignore`).

## MVP (imprescindible)

### 1) Runtime Manager
- [x] Catalogo local de runtimes en backend Tauri.
- [x] PHP: obtener majors desde `releases.json`, cachear, detectar instalaciones locales, instalar TS x64 y descomprimir por linea.
- [x] PHP: `current` global con junction `bin/php/current`.
- [x] PHP: base port configurable y calculo por linea (`9000 -> 9074`, `9081`, etc).
- [x] PHP: gestion de `php.ini` base + overrides por version.
- [x] Node: catalogo real con `nvm`, instalacion por major y selector de version current.
- [x] MariaDB: catalogo de majors desde API oficial, instalacion por major (latest windows x64 zip) y deteccion local.
- [x] MariaDB: selector current y junction `bin/mariadb/current`.
- [x] Nginx: descarga de latest release (GitHub), descompresion y ubicacion en `bin/nginx/<version>`.
- [x] Desinstalacion de binarios reales desde UI/CLI.
- [x] Verificacion de checksums de descargas (SHA256 cuando el provider lo publica).
- [x] Deteccion/recuperacion de binarios corruptos (limpieza automatica de instalaciones invalidas).
- [x] Shims en `bin` por version y `current` (PHP, MariaDB/MySQL, Nginx, Composer).
- [x] `PATH` gestionado por Envloom con una sola entrada (`bin`) para evitar basura.
- [x] Check de updates en background cada hora para PHP/Node/MariaDB (cache de releases 1h).
- [x] Boton `Update` por runtime instalado cuando existe build/version mas nueva.
- [x] Check de updates horario controlado por setting global (`autoUpdate`).

### 2) Bootstrap de entorno
- [x] En primer arranque descarga PHP mas reciente con splash/progreso bloqueante.
- [x] Composer descargado en background (`bin/composer/composer.phar` + shim `bin/composer.cmd`).
- [x] Instalacion de `nvm-windows` en background si no existe.
- [x] Descarga de Nginx en background.
- [x] MariaDB no se descarga al iniciar (instalacion manual desde su pagina).
- [x] Al iniciar app se comprueba si los binarios ya existen antes de descargar.
- [x] Todas las descargas usan una carpeta comun `bin/_downloads`.
- [x] Limpieza de archivos descargados tras descomprimir.
- [x] Nginx y MariaDB se intentan iniciar automaticamente al iniciar app.

### 3) Config por proyecto
- [x] Registro manual de sitios desde UI (persistido en backend `sites.json`).
- [x] Provisionado real de sitios nuevos (Laravel + starter kit + Composer/NPM/migrations).
- [x] `.env` desde `.env.example` cuando falta + `APP_URL` actualizado por dominio.
- [x] Sitios vinculados (`link existing`) no sobreescriben `APP_URL`.
- [ ] Archivo `.envloom.json` por proyecto.
- [ ] Overrides por proyecto (PHP, Node, MariaDB, dominio, puertos, root/public).
- [ ] Herencia de defaults globales.

### 4) Servicios y estado
- [x] Estado real de servicios en backend (`get_service_statuses`).
- [x] Top cards del dashboard muestran estado y version reales.
- [x] Estado intermedio `starting` en index mientras inician servicios.
- [x] Boton `Start all` funcional.
- [x] Boton `Stop all` funcional.
- [x] Auto-start de PHP-FPM, Nginx y MariaDB en bootstrap inicial.
- [x] Auto-start de servicios al iniciar app controlado por setting global (`autoStartServices`).
- [x] Al cerrar la app se detienen automaticamente PHP-FPM, Nginx y MariaDB.
- [x] PHP-FPM gestionado como procesos `php-cgi.exe` por version instalada y puertos configurados.
- [x] Stop de MariaDB reforzado (shutdown + kill por raiz de runtime + verificacion de cierre de puerto).
- [ ] Start/Stop/Restart explicitos de Nginx desde UI/CLI.
- [ ] Start/Stop/Restart explicitos de MariaDB desde UI/CLI.

### 5) MariaDB local
- [x] Reemplazo de MySQL por MariaDB en navegacion y runtime dedicado.
- [x] Config minima en UI: `port` y `root password`.
- [x] Generacion/aplicacion de config base `config/mariadb/my.cnf` y `my.ini` por runtime instalado.
- [x] Selector `current` con junction.
- [x] Inicializacion y arranque con `mysql_install_db.exe`/fallback.
- [x] Password root aplicado/validado con `mysqladmin` (fallback `mariadb-admin`).
- [x] Install de MariaDB pide password root en modal antes de instalar.
- [x] Cambio de password root desde UI se aplica al motor (si esta corriendo) y a config cliente.
- [ ] Import/Export SQL basico.

### 6) UX/UI con shadcn + Tailwind v4
- [x] Layout con sidebar fijo y overflow solo en contenido.
- [x] Pagina PHP funcional.
- [x] Pagina Node funcional.
- [x] Pagina MariaDB funcional (lista versiones + config minima).
- [x] Dashboard con estado de servicios en vivo.
- [ ] Pagina Services funcional con acciones de control.
- [x] Pagina Sites base funcional (listado, detalle, iconos SSL/link y wizard inicial).
- [x] Wizard de Sites conectado a backend Tauri (`list_sites`, `create_site`).
- [x] Sites rediseñado con layout propio (no estilo Herd).
- [x] Skeleton loading en Sites (lista + detalle durante carga inicial).
- [x] Wizard mejorado (modal mas ancho con `!`, pasos visuales, layout mas claro).
- [x] Output del wizard sin duplicados y con autoscroll en provisioning.
- [x] Selector editable de PHP por sitio (aplica y regenera config nginx del sitio).
- [x] Pagina Logs funcional con visor real y selector por fuente.
- [x] Logs UI: selector de nginx por `general` o por sitio, mostrando `access` arriba y `error` abajo.
- [x] Logs UI: selector de PHP por `current` o version especifica.
- [x] Logs UI rediseñado (tabs Runtime/PHP/Nginx/MySql + paneles separados).
- [x] Integracion de `@melloware/react-logviewer` en visores de logs.
- [x] Logs UI simplificado: sin selector de archivo ni filtro manual; solo refresh.
- [x] Pagina Settings basica funcional (auto-start / auto-update) con datos reales.

### 9) Arquitectura backend
- [x] Refactor inicial backend: separacion por capas (`domain`, `infrastructure`, `lib` como composition root).
- [x] Modelos y estado movidos a `src-tauri/src/domain/models.rs`.
- [x] Persistencia/config movidas a `src-tauri/src/infrastructure/persistence.rs`.
- [x] Logging movido a `src-tauri/src/infrastructure/logging.rs`.
- [ ] Segunda fase: separar comandos/casos de uso por modulo (`php`, `mariadb`, `node`, `services`, `bootstrap`).

### 7) Systray
- [ ] Icono con estado global (running/stopped/error).
- [ ] Menu rapido (Start all, Stop all, Restart, versiones, logs).
- [ ] Notificaciones con acciones rapidas.

### 8) Logs y diagnostico
- [x] Logs fisicos de runtime para depuracion (`runtime.log`).
- [x] Captura de errores de arranque de MariaDB/Nginx con contexto.
- [x] Timestamp de logs en formato `YYYY-MM-DD HH:MM:SS`.
- [x] Logs centralizados en carpeta `logs` (mismo nivel que `bin`/`config`/`sites`).
- [x] Nginx: logs globales + logs por sitio (`access` y `error`).
- [x] PHP: log de errores por runtime/version.
- [x] `php.ini` versionado incluye `log_errors` + `error_log` apuntando a `logs/php` de la app.
- [x] MariaDB: `error`, `general` y `slow query` logs en carpeta dedicada.
- [x] Viewer unificado basico (Runtime/Nginx/PHP/MariaDB) en pagina Logs.
- [ ] Filtros por servicio/nivel/fecha.
- [ ] Acciones rapidas (copiar error, abrir config, reiniciar).

### 10) Networking local (Sites)
- [x] Vhosts por sitio en carpeta dedicada `sites/*.conf` (mismo nivel que `bin`/`config`).
- [x] SSL local por sitio con CA local persistente (`sites/ca`) y certs en `sites/certs`.
- [x] Accion por sitio para regenerar SSL + recarga nginx.
- [x] Hosts en bloque propio Envloom (`# Envloom generated Hosts...`) sin tocar bloque Herd.
- [x] Reconciliacion de hosts: dominios Envloom fuera del bloque se mueven al bloque Envloom.
- [x] Elevacion automatica (UAC) para actualizar hosts cuando no hay permisos directos.
- [x] Reconciliacion de `sites/*.conf`: elimina bloques nginx huérfanos de sitios borrados/desvinculados.
- [x] Limpieza de logs nginx por sitio huérfanos al reconciliar sitios.

### 11) Dashboard
- [x] Card de servicios con estado real y estado intermedio `starting`.
- [x] Card de sites (max 10) con nombre, URL, PHP y estado SSL.
- [x] Boton `View more` hacia pagina `Sites`.

### 12) Configuracion global
- [x] Config global Envloom persistida en `~/.envloom/config.json`.
- [x] Settings expuestos por backend (`settings_get`, `settings_set`).
- [x] Compatibilidad de lectura con clave legacy `autoStart` (migracion suave a `autoStartServices`).

## v1 (muy recomendado)
- [ ] CLI `Envloom use <runtime> <version>`.
- [ ] CLI `Envloom current`.
- [ ] CLI `Envloom list <runtime>`.
- [ ] Gestion de hosts locales (`project.test`, subdominios).
- [ ] Integracion con plantillas de proyecto (Laravel, Symfony, WordPress, Node).

## Post-v1
- [ ] Snapshots/backup de entorno.
- [ ] API local para automatizacion.
- [ ] Sistema de plugins (Redis, PostgreSQL, Mailpit, etc).
- [ ] Health checks y metricas basicas.

codex resume 019c7cb1-17d4-7982-9c31-115d74b6ce83
