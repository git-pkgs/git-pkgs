# Package Management

git-pkgs can manage dependencies using the detected package manager. This complements its analysis features: find outdated packages with `git pkgs outdated`, then update them with `git pkgs update`.

## How detection works

git-pkgs looks for lockfiles in the current directory and maps them to package managers:

| Lockfile | Package Manager |
|----------|-----------------|
| bun.lock | bun |
| pnpm-lock.yaml | pnpm |
| yarn.lock | yarn |
| package-lock.json | npm |
| Gemfile.lock | bundler |
| Cargo.lock | cargo |
| go.sum | gomod |
| uv.lock | uv |
| poetry.lock | poetry |
| composer.lock | composer |
| mix.lock | mix |
| pubspec.lock | pub |
| Podfile.lock | cocoapods |

For the npm ecosystem (npm, pnpm, yarn, bun), the specific lockfile determines which tool is used. If you have both `package-lock.json` and `pnpm-lock.yaml`, the more specific one (pnpm) wins.

## Commands

### install

Install dependencies from the lockfile:

```bash
git pkgs install
```

For CI environments, use `--frozen` to fail if the lockfile would change:

```bash
git pkgs install --frozen
```

This translates to:
- npm: `npm ci`
- pnpm: `pnpm install --frozen-lockfile`
- yarn: `yarn install --frozen-lockfile`
- bundler: `bundle install --frozen`
- cargo: `cargo fetch --locked`
- go: `go mod download`

### add

Add a new dependency:

```bash
git pkgs add lodash
git pkgs add lodash 4.17.21      # specific version
git pkgs add lodash --dev        # dev dependency
```

The `--dev` flag maps to each manager's equivalent:
- npm: `--save-dev`
- pnpm: `--save-dev`
- yarn: `--dev`
- bundler: `--group development`
- cargo: `--dev`
- go: (no dev dependencies)
- uv: `--dev`
- poetry: `--group dev`

### remove

Remove a dependency:

```bash
git pkgs remove lodash
```

### update

Update dependencies:

```bash
git pkgs update              # update all
git pkgs update lodash       # update specific package
```

## Multi-ecosystem projects

If your project has multiple lockfiles (e.g., a Rails app with npm for frontend), `install` runs for all detected managers:

```bash
$ git pkgs install
Detected: bundler (Gemfile.lock)
Running: [bundle install]
Detected: npm (package-lock.json)
Running: [npm install]
```

Filter to a specific ecosystem with `-e`:

```bash
git pkgs install -e npm
```

## Overriding detection

Use `-m` to specify the package manager explicitly:

```bash
git pkgs install -m pnpm
git pkgs add lodash -m yarn
```

## Escape hatch

Pass extra arguments to the underlying tool with `-x`:

```bash
git pkgs install -x --legacy-peer-deps
git pkgs add lodash -x --save-exact
git pkgs update -x --latest
```

Multiple `-x` flags accumulate:

```bash
git pkgs install -x --legacy-peer-deps -x --verbose
```

## Dry run

See what would run without executing:

```bash
$ git pkgs install --dry-run
Detected: npm (package-lock.json)
Would run: [npm install]

$ git pkgs install --frozen --dry-run
Detected: npm (package-lock.json)
Would run: [npm ci]
```

## How it works

git-pkgs uses the [managers](https://github.com/git-pkgs/managers) library, which translates generic operations into package manager commands via YAML definitions. The definitions describe each manager's CLI:

```yaml
# from managers/definitions/npm.yaml
name: npm
binary: npm
commands:
  install:
    base: [install]
    flags:
      frozen: [ci]  # changes base command to "npm ci"
  add:
    base: [install]
    args:
      package: {position: 0, required: true}
      version: {suffix: "@"}
    flags:
      dev: [--save-dev]
```

This means git-pkgs doesn't shell out to construct commands - it builds them programmatically with proper argument handling.

## Workflow example

A typical update workflow:

```bash
# See what's outdated
git pkgs outdated

# Update patch versions (safe)
git pkgs update

# Check for vulnerabilities in the updates
git pkgs vulns

# Review what changed
git pkgs diff HEAD

# Commit
git commit -am "Update dependencies"
```

Or update a specific package found to be outdated:

```bash
$ git pkgs outdated
Found 3 outdated dependencies:

Patch updates:
  lodash 4.17.20 -> 4.17.21

$ git pkgs update lodash
Detected: npm (package-lock.json)
Running: [npm update lodash]
```
