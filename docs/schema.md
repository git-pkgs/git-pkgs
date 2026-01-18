# Database Schema

git-pkgs stores dependency history in a SQLite database at `.git/pkgs.sqlite3`. See [internals.md](internals.md) for how the schema is used.

## Tables

### schema_info

Tracks the database schema version for migrations.

| Column | Type | Description |
|--------|------|-------------|
| version | integer | Schema version number |

### branches

Tracks which branches have been analyzed.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| name | text | Branch name (e.g., "main", "develop") |
| last_analyzed_sha | text | SHA of last commit analyzed for incremental updates |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `name` (unique)

### commits

Stores commit metadata for commits that have been analyzed.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| sha | text | Full commit SHA |
| message | text | Commit message |
| author_name | text | Author name |
| author_email | text | Author email |
| committed_at | datetime | Commit timestamp |
| has_dependency_changes | integer | 1 if this commit modified dependencies |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `sha` (unique)

### branch_commits

Join table linking commits to branches. A commit can belong to multiple branches.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| branch_id | integer | Foreign key to branches |
| commit_id | integer | Foreign key to commits |
| position | integer | Order of commit in branch history |

Indexes: `(branch_id, commit_id)` (unique), `(branch_id, position DESC)`

### manifests

Stores manifest file metadata.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| path | text | File path (e.g., "Gemfile", "package.json") |
| ecosystem | text | Package ecosystem (e.g., "rubygems", "npm") |
| kind | text | Manifest type: "manifest" or "lockfile" |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `path`

### dependency_changes

Records each dependency addition, modification, or removal.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| commit_id | integer | Foreign key to commits |
| manifest_id | integer | Foreign key to manifests |
| name | text | Package name |
| ecosystem | text | Package ecosystem |
| purl | text | Package URL (e.g., "pkg:npm/lodash@4.17.21") |
| change_type | text | "added", "modified", or "removed" |
| requirement | text | Version constraint after change |
| previous_requirement | text | Version constraint before change (for modifications) |
| dependency_type | text | "runtime", "development", etc. |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `name`, `ecosystem`, `purl`, `(commit_id, name)`

### dependency_snapshots

Stores the complete dependency state at intervals. Enables fast queries for "what dependencies existed at commit X" without replaying all changes.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| commit_id | integer | Foreign key to commits |
| manifest_id | integer | Foreign key to manifests |
| name | text | Package name |
| ecosystem | text | Package ecosystem |
| purl | text | Package URL |
| requirement | text | Version constraint |
| dependency_type | text | "runtime", "development", etc. |
| integrity | text | SHA256/SHA512 hash from lockfile |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `(commit_id, manifest_id, name)` (unique), `name`, `ecosystem`, `purl`

### packages

Caches package metadata from registries and vulnerability sync status.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| purl | text | Package URL (e.g., "pkg:npm/lodash") |
| ecosystem | text | Package ecosystem |
| name | text | Package name |
| latest_version | text | Latest known version |
| license | text | SPDX license identifier |
| description | text | Package description |
| homepage | text | Homepage URL |
| repository_url | text | Source code repository URL |
| registry_url | text | Package registry URL this data was fetched from |
| supplier_name | text | Package supplier/maintainer name |
| supplier_type | text | Supplier type (person, organization) |
| source | text | Data source: "ecosystems" or "registries" |
| enriched_at | datetime | When package metadata was last fetched |
| vulns_synced_at | datetime | When vulnerabilities were last synced from OSV |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `purl` (unique), `(ecosystem, name)`

### versions

Stores per-version metadata for packages.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| purl | text | Full versioned purl (e.g., "pkg:npm/lodash@4.17.21") |
| package_purl | text | Parent package purl (e.g., "pkg:npm/lodash") |
| license | text | License for this specific version |
| published_at | datetime | When this version was published |
| integrity | text | Integrity hash (e.g., SHA256) |
| source | text | Data source |
| enriched_at | datetime | When metadata was fetched |
| created_at | datetime | |
| updated_at | datetime | |

Indexes: `purl` (unique), `package_purl`

### vulnerabilities

Caches vulnerability data from OSV.

| Column | Type | Description |
|--------|------|-------------|
| id | text | Primary key (CVE-2024-1234, GHSA-xxxx, etc.) |
| aliases | text | Comma-separated alternative IDs |
| severity | text | critical, high, medium, or low |
| cvss_score | real | CVSS numeric score (0.0-10.0) |
| cvss_vector | text | Full CVSS vector string |
| refs | text | Comma-separated reference URLs |
| summary | text | Short description |
| details | text | Full vulnerability details |
| published_at | datetime | When the vulnerability was disclosed |
| withdrawn_at | datetime | When retracted (if ever) |
| modified_at | datetime | When the OSV record was last modified |
| fetched_at | datetime | When we last fetched from OSV |

### vulnerability_packages

Maps which packages are affected by each vulnerability.

| Column | Type | Description |
|--------|------|-------------|
| id | integer | Primary key |
| vulnerability_id | text | Foreign key to vulnerabilities |
| ecosystem | text | OSV ecosystem name (e.g., "RubyGems") |
| package_name | text | Package name |
| affected_versions | text | Version range expression (e.g., "<4.17.21") |
| fixed_versions | text | Comma-separated list of fixed versions |

Indexes: `(ecosystem, package_name)`, `vulnerability_id`, `(vulnerability_id, ecosystem, package_name)` (unique)

## Relationships

```
branches ──┬── branch_commits ──┬── commits
           │                    │
           │                    ├── dependency_changes ──── manifests
           │                    │
           │                    └── dependency_snapshots ── manifests
           │
           └── last_analyzed_sha (references commits.sha)

packages ──── versions (via package_purl)

vulnerabilities ──── vulnerability_packages
```

## Schema Versioning

The `schema_info` table stores the current schema version. When git-pkgs updates with schema changes, commands detect the mismatch and prompt you to run `git pkgs upgrade`, which rebuilds the database.
