# Bisect

`git pkgs bisect` finds when a dependency-related change was introduced using binary search. It works like `git bisect` but only considers commits that modified dependencies, making searches faster when the problem is dependency-related.

If you have 1000 commits between good and bad but only 15 changed dependencies, you're searching 15 commits instead of 1000.

## Basic usage

Start a bisect session:

```bash
git pkgs bisect start
```

Mark the current commit as bad (the problem exists here):

```bash
git pkgs bisect bad
```

Mark a known-good commit (before the problem existed):

```bash
git pkgs bisect good v1.0.0
```

git-pkgs checks out a commit in the middle (only considering commits with dependency changes) and tells you how many steps remain:

```
Bisecting: 12 dependency changes left to test (roughly 4 steps)
[abc1234] Add monitoring dependencies
```

Test this commit and mark it:

```bash
git pkgs bisect good    # or bad, depending on your test
```

Repeat until git-pkgs identifies the culprit:

```
321hijk is the first bad commit

commit 321hijk
Author: Jane <jane@example.com>
Date:   Fri Mar 15 10:30:00 2024

    Add tracking pixel for marketing

Dependencies changed:
  + tracking-pixel@1.0.0
  + pixel-utils@0.2.1
```

End the session and return to your original branch:

```bash
git pkgs bisect reset
```

## Shorthand

You can specify bad and good commits on the start command:

```bash
git pkgs bisect start HEAD v1.0.0
# equivalent to:
# git pkgs bisect start
# git pkgs bisect bad HEAD
# git pkgs bisect good v1.0.0
```

Multiple good commits narrow the search:

```bash
git pkgs bisect start HEAD v1.0.0 v0.9.0 v0.8.0
```

## Automated bisect

The `run` subcommand automates bisecting with a script. The script's exit code determines the result:

- Exit 0: good (problem not present)
- Exit 1-124: bad (problem present)
- Exit 125: skip (can't test this commit)
- Exit 126+: abort bisect

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run ./test-dependencies.sh
```

Example output:

```
running './test-dependencies.sh'
[abc1234] Add monitoring dependencies - bad
[def5678] Update lodash - good
[789abcd] Add analytics - bad
[456defg] Bump minor versions - good
[321hijk] Add tracking pixel - bad
321hijk is the first bad commit
...
```

## Use cases

### Finding when dependencies gained capabilities

Use [capslock](https://github.com/google/capslock) to find when Go dependencies gained network capabilities:

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run sh -c 'go mod tidy && capslock -packages ./... 2>/dev/null | grep -q NETWORK && exit 1 || exit 0'
```

The script:
1. Updates go.mod/go.sum for this commit
2. Runs capslock capability analysis
3. Exits 1 (bad) if NETWORK capability found, 0 (good) otherwise

### Finding when a vulnerability was introduced

Find when a vulnerable version of a package was added:

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run sh -c 'git pkgs vulns --stateless 2>/dev/null | grep -q CVE-2024-1234 && exit 1 || exit 0'
```

### Finding when bundle size increased

Find when JavaScript dependencies caused bundle size to exceed a threshold:

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run sh -c 'npm ci && npm run build && [ $(stat -f%z dist/bundle.js) -lt 500000 ]'
```

### Finding when tests started failing

If tests started failing due to a dependency update:

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run npm test
```

### Finding when an unwanted license appeared

Find when a copyleft license was introduced into a project that needs to stay permissive:

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run sh -c 'git pkgs licenses --stateless 2>/dev/null | grep -qE "GPL|AGPL|LGPL" && exit 1 || exit 0'
```

Or with a specific allow list:

```bash
git pkgs bisect start HEAD v1.0.0
git pkgs bisect run sh -c 'git pkgs licenses --allow=MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause --stateless >/dev/null 2>&1'
```

The `licenses --allow` command exits with code 1 if any dependency has a license not in the allow list, making it work directly with bisect run.

### Finding when a transitive dependency appeared

```bash
git pkgs bisect start --ecosystem=npm HEAD v1.0.0
git pkgs bisect run sh -c 'grep -q "some-transitive-dep" package-lock.json && exit 1 || exit 0'
```

## Filtering

Narrow the search to specific ecosystems, packages, or manifests:

### By ecosystem

Only consider commits that changed npm dependencies:

```bash
git pkgs bisect start --ecosystem=npm HEAD v1.0.0
```

### By package

Only consider commits that touched a specific package:

```bash
git pkgs bisect start --package=lodash HEAD v1.0.0
```

This is useful when you know which package caused the problem but not which version change.

### By manifest

Only consider commits that changed a specific manifest file:

```bash
git pkgs bisect start --manifest=packages/frontend/package.json HEAD v1.0.0
```

Useful in monorepos to isolate changes to a specific package.

## Subcommands

### start

Begin a new bisect session.

```bash
git pkgs bisect start [<bad> [<good>...]] [--ecosystem=<eco>] [--package=<pkg>] [--manifest=<path>]
```

Options:
- `--ecosystem`, `-e`: Only consider commits changing this ecosystem
- `--package`: Only consider commits touching this package
- `--manifest`: Only consider commits changing this manifest

### good

Mark commits as good (before the problem).

```bash
git pkgs bisect good [<rev>...]
```

If no revision is given, marks the current HEAD.

### bad

Mark a commit as bad (problem is present).

```bash
git pkgs bisect bad [<rev>]
```

If no revision is given, marks the current HEAD.

### skip

Skip commits that can't be tested (e.g., won't build).

```bash
git pkgs bisect skip [<rev>...]
```

Skipped commits are excluded from the binary search. If too many commits are skipped, git-pkgs may not be able to find the exact culprit.

### run

Automate bisect with a command.

```bash
git pkgs bisect run <cmd> [<args>...]
```

The command runs at each step. Exit codes determine the result:
- 0: good
- 1-124: bad
- 125: skip
- 126+: abort

### reset

End the bisect session and restore the original HEAD.

```bash
git pkgs bisect reset
```

### log

Show the bisect log for the current session.

```bash
git pkgs bisect log
```

Output can be saved and replayed (future feature).

## How it differs from git bisect

`git pkgs bisect` only considers commits where dependencies changed. This makes it faster for dependency-related issues but means it won't find problems caused by code changes that don't involve dependency modifications.

For general bisecting, use `git bisect`. For dependency-specific problems, `git pkgs bisect` gets you there faster.

| Feature | git bisect | git pkgs bisect |
|---------|------------|-----------------|
| Searches all commits | Yes | No |
| Searches dependency changes only | No | Yes |
| Requires clean working directory | Yes | Yes |
| Automated with run | Yes | Yes |
| Filtering by ecosystem/package | No | Yes |

## Requirements

- The git-pkgs database must exist (`git pkgs init`)
- Working directory must be clean (no uncommitted changes)
- The good and bad commits must be in the indexed branch
