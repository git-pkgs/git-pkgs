# Internals

git-pkgs walks a repository's commit history, parses manifest files at each commit, and stores dependency changes in a SQLite database. This lets you query what changed, when, and who did it.

The tool works with two types of data. Intrinsic data comes from your git history: dependency names, versions from manifests, who added them, when, and why. Commands like `list`, `history`, `blame`, `diff`, and `stale` use only intrinsic data and require no network access. Extrinsic data comes from external sources: vulnerability info from [OSV](https://osv.dev), and registry metadata (latest versions, licenses) from [ecosyste.ms](https://packages.ecosyste.ms/). Commands like `vulns`, `outdated`, and `licenses` fetch and cache this external data.

## Package Structure

```
cmd/                    CLI commands (cobra)
internal/
  analyzer/             Manifest parsing and change detection
  database/             SQLite layer (queries, schema, batch writer)
  enrichment/           Package metadata fetching (ecosyste.ms or direct registry)
  git/                  Repository wrapper (go-git)
  indexer/              Orchestrates history walking
  osv/                  OSV API client
```

## Entry Point

The CLI uses [cobra](https://github.com/spf13/cobra). Each command is registered in `cmd/` via `init()` functions. The root command handles global flags (`--quiet`, `--color=auto`, `--no-pager`) and dispatches to subcommands.

## Database

`internal/database` manages the SQLite connection using [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) (pure Go, no CGO). The database path defaults to `.git/pkgs.sqlite3` but can be overridden with `GIT_PKGS_DB`.

The schema has ten tables. Six handle dependency tracking:

- `commits` holds commit metadata plus a flag indicating whether it changed dependencies
- `branches` tracks which branches have been analyzed and their last processed SHA
- `branch_commits` is a join table preserving commit order within each branch
- `manifests` stores file paths with their ecosystem (npm, rubygems, etc.) and kind (manifest vs lockfile)
- `dependency_changes` records every add, modify, or remove event
- `dependency_snapshots` stores full dependency state at intervals, including lockfile integrity hashes

Four more support vulnerability scanning and package enrichment:

- `packages` caches package metadata and vulnerability sync status
- `versions` stores per-version metadata (license, published date) for time-travel queries
- `vulnerabilities` caches CVE/GHSA data fetched from OSV
- `vulnerability_packages` maps which packages are affected by each vulnerability

See [schema.md](schema.md) for the full schema.

## Why Snapshots?

Replaying thousands of change records to answer "what dependencies existed at commit X?" would be slow. Instead, we store the complete dependency set every 50 commits (by default). Point-in-time queries find the nearest snapshot and replay only the changes since then.

## Git Access

`internal/git` wraps [go-git](https://github.com/go-git/go-git) for repository operations. The `Repository` type provides:

- `CurrentBranch()` - get the current branch name
- `ResolveRevision()` - resolve refs to commit hashes
- `CommitObject()` - get commit metadata
- `Log()` - iterate commit history
- `FileAtCommit()` - read file contents at a specific commit

For large repositories, the analyzer prefetches diffs using a single `git log` shell command rather than individual go-git calls. This provides better performance and avoids thread-safety issues in go-git.

## Manifest Analysis

`internal/analyzer` detects and parses manifest files using [git-pkgs/manifests](https://github.com/git-pkgs/manifests), which supports 35+ ecosystems including npm, RubyGems, PyPI, Cargo, Go modules, and more.

The analyzer maintains caches to avoid redundant work:

- `blobCache` - parsed manifest contents keyed by git blob OID. If two commits have the same OID for a file, we parse it once.
- `diffCache` - prefetched diffs to avoid repeated git operations

The `AnalyzeCommit` method compares manifest state before and after a commit to detect changes:

```go
added = afterDeps - beforeDeps
removed = beforeDeps - afterDeps
modified = intersection where requirement changed
```

Merge commits are skipped since they don't introduce new changes.

## The Init Process

When you run `git pkgs init`:

1. Creates the database with optimized settings for bulk writes (WAL mode, synchronous off)
2. Walks commit history from oldest to newest
3. Prefetches git diffs in batch using shell commands
4. For each commit, analyzes manifest changes
5. Batches inserts in transactions (default 500 commits per batch)
6. Creates dependency snapshots every 50 commits with changes
7. Switches to optimized read settings when complete

The `BatchWriter` in `internal/database` buffers records and flushes them in transactions for better performance.

## Incremental Updates

`git pkgs reindex` picks up where init left off. Each branch stores its `last_analyzed_sha`. Reindex walks from that commit to HEAD, processes new commits, and advances the checkpoint. Git hooks installed during init run reindex automatically after commits and merges.

## Schema Upgrades

The database stores its schema version in the `schema_info` table. When git-pkgs updates and the schema changes, commands detect the mismatch and prompt you to run `git pkgs upgrade`, which rebuilds the database from scratch.

## Point-in-Time Reconstruction

Several commands need the full dependency set at a specific commit. The algorithm:

1. Find the latest snapshot at or before the target commit
2. Load that snapshot as the initial state
3. Query changes between the snapshot and target
4. Apply each change: added/modified updates the set, removed deletes

This is handled by `GetDependenciesAtRef` and related methods in `internal/database/queries.go`.

## Git Hooks

The `hooks` command installs shell scripts into `.git/hooks/` that run `git pkgs reindex` after commits and merges. Init installs these by default.

The hook script suppresses errors so a failed reindex doesn't block normal git operations:

```sh
#!/bin/sh
git pkgs reindex 2>/dev/null || true
```

## Diff Driver

The `diff-driver` command sets up a git textconv filter that transforms lockfiles before diffing. Instead of raw lockfile churn, `git diff` shows a sorted dependency list.

Installation configures `diff.pkgs.textconv` in git config and adds patterns to `.gitattributes`. When git diffs a lockfile, it calls `git-pkgs diff-driver <path>` on each version, which outputs one line per dependency.

## Vulnerability Scanning

The `vulns` command checks dependencies against [OSV](https://osv.dev). The `internal/osv` package wraps the OSV REST API, using batch queries to check multiple packages per request.

Vulnerability data is cached in the database with a 24-hour TTL. The scan process:

1. Get dependencies at the target commit
2. Filter to ecosystems with OSV support
3. Check which packages need syncing (never synced or stale)
4. Batch query OSV for those packages
5. Store vulnerability data locally
6. Match version ranges against actual versions using [git-pkgs/vers](https://github.com/git-pkgs/vers)
7. Exclude withdrawn vulnerabilities

See [vulns.md](vulns.md) for command documentation.

## Package Enrichment

The `outdated`, `licenses`, `sbom`, and `integrity --registry` commands fetch metadata from external sources. The `internal/enrichment` package provides a unified interface with two backends:

- **ecosyste.ms** - Bulk API queries via [ecosyste-ms/ecosystems-go](https://github.com/ecosyste-ms/ecosystems-go). Efficient for public packages.
- **registries** - Direct queries to package registries via [git-pkgs/registries](https://github.com/git-pkgs/registries). Required for private registries.

By default, a hybrid approach routes requests based on PURL qualifiers: packages with a `repository_url` qualifier (indicating a private registry) go directly to that registry, while public packages go through ecosyste.ms. Set `git config pkgs.direct true` or `GIT_PKGS_DIRECT=1` to skip ecosyste.ms and query all registries directly.

Data is cached in the `packages` and `versions` tables with a 24-hour TTL. The `packages` table stores provenance: `repository_url` (the registry queried) and `source` (ecosystems or registries).

## Package Management

The `install`, `add`, `remove`, and `update` commands use [git-pkgs/managers](https://github.com/git-pkgs/managers) to translate generic operations into package manager CLI commands. The library builds commands programmatically from YAML definitions rather than constructing shell strings.

Detection works by looking for lockfiles and mapping them to package managers. For the npm ecosystem, the specific lockfile (package-lock.json vs pnpm-lock.yaml vs yarn.lock) determines which tool is used.

## Output Handling

Commands support multiple output formats (text, JSON, SARIF) and respect terminal settings:

- Pager follows git precedence: `GIT_PAGER` env, `core.pager` config, `PAGER` env, then `less`
- Color respects `NO_COLOR` environment variable and `color.pkgs` git config
- TTY detection disables colors and paging when not connected to a terminal

## Performance

Typical init speed is 100-500 commits per second depending on repository size and manifest complexity. The main optimizations:

- Blob OID caching avoids re-parsing unchanged manifests
- Batch prefetching of git diffs in a single command
- Batched database writes (500 commits per transaction)
- Deferred index creation until after bulk loading
- WAL mode and tuned PRAGMAs during writes

Environment variables for tuning (hidden flags on init):
- `--batch-size` - commits per transaction (default 500)
- `--snapshot-interval` - snapshots every N commits with changes (default 50)

Use `--cpuprofile` and `--memprofile` flags on init for profiling with pprof.
