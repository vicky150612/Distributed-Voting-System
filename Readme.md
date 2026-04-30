# Distributed Voting System

A multi-process, multi-region electronic voting system implemented in C. The system uses a three-tier architecture consisting of a **Central Authority**, **Regional Servers**, and **Clients**, communicating via POSIX IPC mechanisms and TCP sockets.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Components](#components)
  - [Central Authority](#central-authority)
  - [Regional Server](#regional-server)
  - [Client](#client)
  - [Common Utilities](#common-utilities)
- [Communication Model](#communication-model)
- [Security Features](#security-features)
- [Building](#building)
- [Running the System](#running-the-system)
- [Default Credentials](#default-credentials)
- [Data Files](#data-files)

---

## Architecture Overview

```
                    ┌─────────────────────┐
                    │  Central Authority  │
                    │   (authority)       │
                    └────────┬────────────┘
                             │
              POSIX Message Queues + Shared Memory
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
  ┌───────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
  │  Regional    │   │  Regional    │   │  Regional    │
  │  Server R1   │   │  Server R2   │   │  Server R3   │
  │  :8080       │   │  :8081       │   │  :8082       │
  └───────┬──────┘   └───────┬──────┘   └───────┬──────┘
          │                  │                  │
          └──────────── TCP Sockets ────────────┘
                             │
                      ┌──────▼──────┐
                      │   Client    │
                      │  (voter /   │
                      │   admin)    │
                      └─────────────┘
```

---

## Project Structure

```
Project/
├── Makefile
├── central_authority/
│   ├── authority.c          # Main authority logic
│   ├── authority.h
│   └── voted_global.txt     # Global voter deduplication log
├── regional_server/
│   ├── server.c             # TCP server + IPC listener
│   ├── server.h
│   ├── auth.c               # Voter/admin authentication & token management
│   ├── auth.h
│   ├── vote.c               # Vote casting, tally, audit log
│   ├── vote.h
│   └── data/                # Auto-created at runtime
│       ├── R1/
│       │   ├── voterlist.txt
│       │   ├── voted.txt
│       │   ├── tally.txt
│       │   └── audit.log
│       ├── R2/ ...
│       └── R3/ ...
├── client/
│   ├── client.c             # Interactive CLI for voters and admins
│   └── client.h
└── common/
    ├── utils.c              # File locking + djb2 hash
    └── utils.h              # Shared constants, structs, IPC keys
```

---

## Components

### Central Authority

The Central Authority is the top-level control process. It must be started **before** any Regional Server.

**Responsibilities:**

- Authenticates the operator with a password on startup.
- Registers Regional Servers that connect via IPC.
- Enables or disables voting on all regions or a specific region using UNIX signals (`SIGUSR1` / `SIGUSR2`).
- Requests audit verification from all connected servers.
- Collects vote tallies via shared memory and performs a global integrity check (comparing aggregated vote counts against the unique-voter deduplication file).
- Cleans up all IPC resources on exit and signals all servers to shut down.

**Interactive Menu:**

| Option | Action                           |
| ------ | -------------------------------- |
| 1      | Enable voting — all regions      |
| 2      | Disable voting — all regions     |
| 3      | Enable voting — specific region  |
| 4      | Disable voting — specific region |
| 5      | Verify audit logs on all servers |
| 6      | Collect and display results      |
| 7      | Shut down all servers and exit   |

---

### Regional Server

Each Regional Server handles one geographic region (`R1`, `R2`, or `R3`) and listens on a dedicated TCP port.

| Region | Port |
| ------ | ---- |
| R1     | 8080 |
| R2     | 8081 |
| R3     | 8082 |

**Responsibilities:**

- Connects to the Central Authority via message queue on startup.
- Spawns a background thread to listen for authority commands (`VERIFY`, `RESULTS`).
- Accepts concurrent client connections via `pthreads`, one thread per client.
- Manages per-region voter lists, voted records, tallies, and audit logs.
- Enforces the voting-enabled flag (toggled by signals from the Authority).

**Voting Flow:**

1. Client sends `LOGIN <voter_id>` → server validates voter eligibility and returns a signed token.
2. Client sends `VOTE <token> <candidate>` → server validates the token, checks for duplicate votes both locally and against the Authority, updates the tally, and appends to the audit log.

**Admin Flow:**

1. Client sends `ADMIN_AUTH <hash>` → server validates the region-specific admin password hash.
2. Authenticated admin can enable/disable voting locally or trigger audit verification.

---

### Client

The Client is an interactive CLI that connects to one Regional Server per session.

**Startup:** Select a region (`R1`, `R2`, or `R3`), then choose a role:

- **Voter** — Enter your voter ID to receive a session token, then cast a vote for a candidate (`A`–`Z`).
- **Admin** — Enter the region admin password to access the admin menu (enable/disable voting, verify audit log).

---

### Common Utilities

Shared across all components (`common/utils.h`, `common/utils.c`):

- **`hash(char *str)`** — djb2 hash function used for password verification, token signing, and audit log chaining.
- **`lock_file(fd)`** / **`read_lock_file(fd)`** / **`unlock_file(fd)`** — POSIX advisory file locking (`fcntl`) for safe concurrent file access.
- **Shared constants** — IPC keys, `MAX_SERVERS`, `MAX_CANDIDATES`, token secret, token expiry, shared memory keys.
- **Shared structs** — `struct msg` (IPC message), `result_entry`, `result_shm` (shared memory layout).

---

## Communication Model

| Channel                                        | Used Between                 | Purpose                                                                 |
| ---------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------- |
| POSIX Message Queue (`KEY_REQ` / `KEY_RES`)    | Authority ↔ Regional Servers | Server registration, vote deduplication checks, verify/results commands |
| POSIX Shared Memory (`SHM_KEY`)                | Authority → Regional Servers | Server registry (PID, region, connected flag)                           |
| POSIX Shared Memory (`SHM_RESULT_KEY`)         | Authority ↔ Regional Servers | Result collection (vote tallies per region)                             |
| UNIX Signals (`SIGUSR1`, `SIGUSR2`, `SIGTERM`) | Authority → Regional Servers | Enable/disable voting, shutdown                                         |
| TCP Sockets                                    | Regional Servers ↔ Clients   | Login, voting, admin sessions                                           |
| File I/O (with `fcntl` locking)                | Within each process          | Voter lists, voted records, tallies, audit logs                         |

---

## Security Features

| Feature                    | Implementation                                                                                        |
| -------------------------- | ----------------------------------------------------------------------------------------------------- |
| Authority password         | djb2 hash comparison at startup                                                                       |
| Region admin passwords     | Per-region password hashes (`R1`/`R2`/`R3`)                                                           |
| Voter token                | Signed with `voter_id + timestamp + SECRET`; expires after 300 seconds                                |
| Double-vote prevention     | Local `voted.txt` per region + global `voted_global.txt` via Authority                                |
| Audit log integrity        | Hash-chained log entries: each entry stores `hash(prev_hash + voter_id + candidate)`                  |
| Audit verification         | Replays the hash chain and detects missing log, entry number mismatch, broken chain, or tampered data |
| Concurrent file access     | POSIX `fcntl` advisory write/read locks on all shared files                                           |
| Integrity check on results | Aggregated vote count compared against global unique-voter count                                      |

---

## Building

**Requirements:** GCC, POSIX-compliant Linux system, `pthreads` library.

```bash
# Build all three binaries into bin/
make

# Or build individually:
make bin/authority
make bin/server
make bin/client

# Clean build artifacts:
make clean
```

Binaries are placed in `bin/`:

```
bin/
├── authority
├── server
└── client
```

---

## Running the System

The components must be started in the following order. Open a separate terminal for each.

### Step 1 — Start the Central Authority

```bash
./bin/authority
```

Enter the authority password when prompted. The authority will then wait for Regional Servers to connect.

### Step 2 — Start Regional Servers

Start one or more servers, each in its own terminal:

```bash
./bin/server    # When prompted, enter: R1
./bin/server    # When prompted, enter: R2
./bin/server    # When prompted, enter: R3
```

Each server will confirm successful connection to the Authority and begin listening on its assigned port.

### Step 3 — Enable Voting

From the Central Authority menu, select **option 1** (Enable voting — all regions) or **option 3** to enable a specific region.

### Step 4 — Connect Clients

```bash
./bin/client
```

Select the region, then choose **Voter** or **Admin** role and follow the prompts.

### Step 5 — Collect Results

From the Central Authority menu, select **option 6** to disable voting, collect tallies from all servers, and display the final results with an integrity check.

---

## Default Credentials

| Role              | Credential |
| ----------------- | ---------- |
| Central Authority | `admin123` |
| Region R1 Admin   | `AdminR1`  |
| Region R2 Admin   | `AdminR2`  |
| Region R3 Admin   | `AdminR3`  |

---

## Data Files

All runtime data is stored under `regional_server/data/<region>/` and is created automatically on first server start.

| File            | Description                                              |
| --------------- | -------------------------------------------------------- |
| `voterlist.txt` | Eligible voter IDs (pre-populated with IDs 101–140)      |
| `voted.txt`     | IDs of voters who have already voted in this region      |
| `tally.txt`     | Running vote count per candidate (`<Candidate> <count>`) |
| `audit.log`     | Tamper-evident hash-chained log of every vote cast       |

The global deduplication file `central_authority/voted_global.txt` is managed exclusively by the Central Authority and records every voter ID that has voted across all regions.
