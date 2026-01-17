# git-pkgs

A git subcommand for tracking package dependencies across git history. Analyzes your repository to show when dependencies were added, modified, or removed, who made those changes, and why.

[Installation](#installation) · [Quick start](#quick-start) · [Commands](#commands) · [Configuration](#configuration) · [Contributing](#contributing)

## Why this exists

Your lockfile shows what dependencies you have, but it doesn't show how you got here, and `git log Gemfile.lock` is useless noise. git-pkgs indexes your dependency history into a queryable database so you can ask questions like: when did we add this? who added it? what changed between these two releases? has anyone touched this in the last year?

For best results, commit your lockfiles. Manifests show version ranges but lockfiles show what actually got installed, including transitive dependencies.

It works across many ecosystems (Gemfile, package.json, Dockerfile, GitHub Actions workflows) giving you one unified history instead of separate tools per ecosystem. The database lives in your `.git` directory where you can use it in CI to catch dependency changes in pull requests.

The core commands (`list`, `history`, `blame`, `diff`, `stale`, etc.) work entirely from your git history with no network access. Additional commands fetch external data: `vulns` checks [OSV](https://osv.dev) for known CVEs, while `outdated` and `licenses` query [ecosyste.ms](https://packages.ecosyste.ms/) for registry metadata.

## Installation

```bash
brew tap git-pkgs/git-pkgs
brew install git-pkgs
```

Or download a binary from the [releases page](https://github.com/git-pkgs/git-pkgs/releases).

Or build from source:

```bash
go install github.com/git-pkgs/git-pkgs@latest
```

## Quick start

```bash
cd your-repo
git pkgs init           # analyze history (one-time)
git pkgs list           # show current dependencies
git pkgs stats          # see overview
git pkgs blame          # who added each dependency
git pkgs history        # all dependency changes over time
git pkgs history rails  # track a specific package
git pkgs why rails      # why was this added?
git pkgs diff --from=HEAD~10  # what changed recently?
git pkgs diff --from=main --to=feature  # compare branches
git pkgs vulns          # scan for known CVEs
git pkgs vulns blame    # who introduced each vulnerability
git pkgs outdated       # find packages with newer versions
git pkgs update         # update all dependencies
git pkgs add lodash     # add a package
```

## Commands

### Initialize the database

```bash
git pkgs init
```

Walks through git history and builds a SQLite database of dependency changes, stored in `.git/pkgs.sqlite3`.

Options:
- `--branch=NAME` - analyze a specific branch (default: default branch)
- `--since=SHA` - start analysis from a specific commit
- `--force` - rebuild the database from scratch
- `--no-hooks` - skip installing git hooks (hooks are installed by default)

### Database info

```bash
git pkgs info
```

Shows database size and row counts:

```
Database Info
========================================

Location: /path/to/repo/.git/pkgs.sqlite3
Size: 8.3 MB

Row Counts
----------------------------------------
  Branches                        1
  Commits                      3988
  Branch-Commits               3988
  Manifests                       9
  Dependency Changes           4732
  Dependency Snapshots        28239
  ----------------------------------
  Total                       40957
```

### List dependencies

```bash
git pkgs list
git pkgs list --commit=abc123
git pkgs list --ecosystem=rubygems
git pkgs list --manifest=Gemfile
git pkgs list --stateless           # parse manifests directly, no database needed
```

Example output:
```
Gemfile (rubygems):
  bootsnap >= 0 [runtime]
  bootstrap = 4.6.2 [runtime]
  bugsnag >= 0 [runtime]
  rails = 8.0.1 [runtime]
  sidekiq >= 0 [runtime]
  ...
```

### View dependency history

```bash
git pkgs history                       # all dependency changes
git pkgs history rails                 # changes for a specific package
git pkgs history --author=alice        # filter by author
git pkgs history --since=2024-01-01    # changes after date
git pkgs history --ecosystem=rubygems  # filter by ecosystem
```

Shows when packages were added, updated, or removed:

```
History for rails:

2016-12-16 Added = 5.0.0.1
  Commit: e323669 Hello World
  Author: Andrew Nesbitt <andrew@example.com>
  Manifest: Gemfile

2016-12-21 Updated = 5.0.0.1 -> = 5.0.1
  Commit: 0c70eee Update rails to 5.0.1
  Author: Andrew Nesbitt <andrew@example.com>
  Manifest: Gemfile

2024-11-21 Updated = 7.2.2 -> = 8.0.0
  Commit: 86a07f4 Upgrade to Rails 8
  Author: Andrew Nesbitt <andrew@example.com>
  Manifest: Gemfile
```

### Blame

Show who added each current dependency:

```bash
git pkgs blame
git pkgs blame --ecosystem=rubygems
```

Example output:
```
Gemfile (rubygems):
  bootsnap                        Andrew Nesbitt     2018-04-10  7da4369
  bootstrap                       Andrew Nesbitt     2018-08-02  0b39dc0
  bugsnag                         Andrew Nesbitt     2016-12-23  a87f1bf
  factory_bot                     Lewis Buckley      2017-12-25  f6cceb0
  faraday                         Andrew Nesbitt     2021-11-25  98de229
  jwt                             Andrew Nesbitt     2018-09-10  a39f0ea
  octokit                         Andrew Nesbitt     2016-12-16  e323669
  omniauth-rails_csrf_protection  dependabot[bot]    2021-11-02  02474ab
  rails                           Andrew Nesbitt     2016-12-16  e323669
  sidekiq                         Mark Tareshawty    2018-02-19  29a1c70
```

### Show statistics

```bash
git pkgs stats
git pkgs stats --by-author         # who added the most dependencies
git pkgs stats --ecosystem=npm     # filter by ecosystem
git pkgs stats --since=2024-01-01  # changes after date
git pkgs stats --until=2024-12-31  # changes before date
```

Example output:
```
Dependency Statistics
========================================

Branch: main
Commits analyzed: 3988
Commits with changes: 2531

Current Dependencies
--------------------
Total: 250
  rubygems: 232
  actions: 14
  docker: 4

Dependency Changes
--------------------
Total changes: 4732
  added: 391
  modified: 4200
  removed: 141

Most Changed Dependencies
-------------------------
  rails (rubygems): 135 changes
  pagy (rubygems): 116 changes
  nokogiri (rubygems): 85 changes
  puma (rubygems): 73 changes

Manifest Files
--------------
  Gemfile (rubygems): 294 changes
  Gemfile.lock (rubygems): 4269 changes
  .github/workflows/ci.yml (actions): 36 changes
```

### Explain why a dependency exists

```bash
git pkgs why rails
```

This shows the commit that added the dependency along with the author and message.

### Dependency tree

```bash
git pkgs tree
git pkgs tree --ecosystem=rubygems
```

This shows dependencies grouped by type (runtime, development, etc).

### Find stale dependencies

```bash
git pkgs stale                  # list deps by how long since last touched
git pkgs stale --days=365       # only show deps untouched for a year
git pkgs stale --ecosystem=npm  # filter by ecosystem
```

Shows dependencies sorted by how long since they were last changed in your repo. Useful for finding packages that may have been forgotten or need review.

### Find outdated dependencies

```bash
git pkgs outdated               # show packages with newer versions available
git pkgs outdated --major       # only major version updates
git pkgs outdated --minor       # minor and major updates (skip patch)
git pkgs outdated --at v2.0     # what was outdated when we released v2.0?
git pkgs outdated --at 2024-03-01  # what was outdated on this date?
git pkgs outdated --stateless   # no database needed
```

Checks package registries (via [ecosyste.ms](https://packages.ecosyste.ms/)) to find dependencies with newer versions available. Major updates are shown in red, minor in yellow, patch in cyan.

The `--at` flag enables time travel: pass a date (YYYY-MM-DD) or any git ref (tag, branch, commit SHA) to see what was outdated at that point in time. When given a git ref, it uses the commit's date.

### Manage dependencies

git-pkgs can run package manager commands for you, detecting the right tool from your lockfiles:

```bash
git pkgs install              # install from lockfile
git pkgs install --frozen     # CI mode (fail if lockfile would change)
git pkgs add lodash           # add a package
git pkgs add rails --dev      # add as dev dependency
git pkgs add lodash 4.17.21   # add specific version
git pkgs remove lodash        # remove a package
git pkgs update               # update all dependencies
git pkgs update lodash        # update specific package
```

Supports npm, pnpm, yarn, bun, bundler, cargo, go, uv, poetry, composer, mix, pub, and cocoapods. The package manager is detected from lockfiles in the current directory.

Use `-m` to override detection, `-x` to pass extra arguments to the underlying tool:

```bash
git pkgs install -m pnpm                    # force pnpm
git pkgs install -x --legacy-peer-deps      # pass extra flags
git pkgs add lodash -x --save-exact         # npm --save-exact
```

### Check licenses

```bash
git pkgs licenses               # show license for each dependency
git pkgs licenses --permissive  # flag copyleft licenses
git pkgs licenses --allow=MIT,Apache-2.0  # explicit allow list
git pkgs licenses --group       # group output by license
git pkgs licenses --stateless   # no database needed
```

Fetches license information from package registries. Exits with code 1 if violations are found, making it suitable for CI.

### Vulnerability scanning

Scan dependencies for known CVEs using the [OSV database](https://osv.dev). Because git-pkgs tracks the full history of every dependency change, it provides context that static scanners can't: who introduced a vulnerability, when it was fixed, and how long you were exposed.

```bash
git pkgs vulns                  # scan current dependencies
git pkgs vulns v1.0.0           # scan at a tag, branch, or commit
git pkgs vulns -s high          # only critical and high severity
git pkgs vulns -e npm           # filter by ecosystem
git pkgs vulns -f sarif         # output for GitHub code scanning
```

Subcommands for historical analysis:

```bash
git pkgs vulns blame            # who introduced each vulnerability
git pkgs vulns blame --all-time # include fixed vulnerabilities
git pkgs vulns praise           # who fixed vulnerabilities
git pkgs vulns praise --summary # author leaderboard
git pkgs vulns exposure         # remediation metrics (CRA compliance)
git pkgs vulns diff main feature # compare vulnerability state between refs
git pkgs vulns log              # commits that introduced or fixed vulns
git pkgs vulns history lodash   # vulnerability timeline for a package
git pkgs vulns show CVE-2024-1234  # details about a specific CVE
```

Output formats: `text` (default), `json`, and `sarif`. SARIF integrates with GitHub Advanced Security:

```yaml
- run: git pkgs vulns --stateless -f sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Vulnerability data is cached locally and refreshed automatically when stale (>24h). Use `git pkgs vulns sync --refresh` to force an update.

### Integrity verification

Show SHA256 hashes from lockfiles. Modern lockfiles include checksums that verify package contents haven't been tampered with.

```bash
git pkgs integrity              # show hashes for current dependencies
git pkgs integrity --drift      # detect same version with different hashes
git pkgs integrity -f json      # JSON output
git pkgs integrity --stateless  # no database needed
```

The `--drift` flag scans your history for packages where the same version has different integrity hashes, which could indicate a supply chain issue.

### SBOM export

Export dependencies as a Software Bill of Materials in CycloneDX or SPDX format:

```bash
git pkgs sbom                      # CycloneDX JSON (default)
git pkgs sbom --type spdx          # SPDX JSON
git pkgs sbom -f xml               # XML instead of JSON
git pkgs sbom --name my-project    # custom project name
git pkgs sbom --stateless          # no database needed
```

Includes package URLs (purls), versions, and licenses (fetched from registries). Use `--skip-enrichment` to omit license lookups.

### Diff between commits

```bash
git pkgs diff --from=abc123 --to=def456
git pkgs diff --from=HEAD~10
git pkgs diff main..feature --stateless  # no database needed
```

This shows added, removed, and modified packages with version info.

### Show changes in a commit

```bash
git pkgs show              # show dependency changes in HEAD
git pkgs show abc123       # specific commit
git pkgs show HEAD~5       # relative ref
git pkgs show --stateless  # no database needed
```

Like `git show` but for dependencies. Shows what was added, modified, or removed in a single commit.

### Find where a package is declared

```bash
git pkgs where rails           # find in manifest files
git pkgs where lodash -C 2     # show 2 lines of context
git pkgs where express --ecosystem=npm
```

Shows which manifest files declare a package and the exact line:

```
Gemfile:5:gem "rails", "~> 7.0"
Gemfile.lock:142:    rails (7.0.8)
```

Like `grep` but scoped to manifest files that git-pkgs knows about.

### List commits with dependency changes

```bash
git pkgs log                  # recent commits with dependency changes
git pkgs log --author=alice   # filter by author
git pkgs log -n 50            # show more commits
```

Like `git log` but only shows commits that changed dependencies, with the changes listed under each commit.

### Keep database updated

After the initial analysis, the database updates automatically via git hooks installed during init. You can also update manually:

```bash
git pkgs reindex
```

To manage hooks separately:

```bash
git pkgs hooks              # show hook status
git pkgs hooks --install    # install hooks
git pkgs hooks --uninstall  # remove hooks
```

### Upgrading

After updating git-pkgs, you may need to rebuild the database if the schema has changed:

```bash
git pkgs upgrade
```

This is detected automatically and you'll see a message if an upgrade is needed.

### Show database schema

```bash
git pkgs schema                   # human-readable table format
git pkgs schema --format=sql      # CREATE TABLE statements
git pkgs schema --format=json     # JSON structure
git pkgs schema --format=markdown # markdown tables
```

### CI usage

You can run git-pkgs in CI to show dependency changes in pull requests. Use `--stateless` to skip database initialization for faster runs:

```yaml
# .github/workflows/deps.yml
name: Dependencies

on: pull_request

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: |
          curl -L https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs
      - run: ./git-pkgs diff --from=origin/${{ github.base_ref }} --to=HEAD --stateless
```

### Diff driver

Install a git textconv driver that shows semantic dependency changes instead of raw lockfile diffs:

```bash
git pkgs diff-driver --install
```

Now `git diff` on lockfiles shows a sorted dependency list instead of raw lockfile changes:

```diff
diff --git a/Gemfile.lock b/Gemfile.lock
--- a/Gemfile.lock
+++ b/Gemfile.lock
@@ -1,3 +1,3 @@
+kamal 1.0.0
-puma 5.0.0
+puma 6.0.0
 rails 7.0.0
-sidekiq 6.0.0
```

Use `git diff --no-textconv` to see the raw lockfile diff. To remove: `git pkgs diff-driver --uninstall`

### Shell completions

Enable tab completion for commands:

```bash
# Bash: add to ~/.bashrc
eval "$(git pkgs completions bash)"

# Zsh: add to ~/.zshrc
eval "$(git pkgs completions zsh)"

# Or auto-install to standard completion directories
git pkgs completions install
```

## Configuration

git-pkgs respects [standard git configuration](https://git-scm.com/docs/git-config).

**Colors** are enabled when writing to a terminal. Disable with `NO_COLOR=1`, `git config color.ui never`, or `git config color.pkgs never` for git-pkgs only.

**Pager** follows git's precedence: `GIT_PAGER` env, `core.pager` config, `PAGER` env, then `less -FRSX`. Use `--no-pager` flag or `git config core.pager cat` to disable.

**Ecosystem filtering** lets you limit which package ecosystems are tracked:

```bash
git config --add pkgs.ecosystems rubygems
git config --add pkgs.ecosystems npm
git pkgs info --ecosystems  # show enabled/disabled ecosystems
```

**Ignored paths** let you skip directories or files from analysis:

```bash
git config --add pkgs.ignoredDirs third_party
git config --add pkgs.ignoredFiles test/fixtures/package.json
```

**Environment variables:**

- `GIT_DIR` - git directory location (standard git variable)
- `GIT_PKGS_DB` - database path (default: `.git/pkgs.sqlite3`)

## Supported ecosystems

git-pkgs uses [github.com/git-pkgs/manifests](https://github.com/git-pkgs/manifests) for parsing, supporting:

Actions, Cargo, CocoaPods, Composer, Go, Hex, Maven, npm, NuGet, Pub, PyPI, RubyGems, and more.

## Contributing

Bug reports, feature requests, and pull requests are welcome. If you're unsure about a change, open an issue first to discuss it.

## License

MIT
