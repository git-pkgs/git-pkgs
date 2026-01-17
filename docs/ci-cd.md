# CI/CD Usage

git-pkgs works well in CI pipelines for dependency analysis, vulnerability scanning, and automated updates.

## GitHub Actions

### Show dependency changes in PRs

```yaml
name: Dependencies
on: pull_request

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Show dependency changes
        run: ./git-pkgs diff --from=origin/${{ github.base_ref }} --to=HEAD --stateless
```

### Vulnerability scanning with SARIF

Upload results to GitHub Security tab:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:

jobs:
  vulns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Scan for vulnerabilities
        run: ./git-pkgs vulns --stateless -f sarif > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Block PRs with high severity vulnerabilities

```yaml
name: Security Gate
on: pull_request

jobs:
  vulns:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Check for high/critical vulnerabilities
        run: ./git-pkgs vulns --stateless -s high
        # Exits non-zero if vulnerabilities found
```

### License compliance

```yaml
name: License Check
on: pull_request

jobs:
  licenses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Check licenses
        run: ./git-pkgs licenses --stateless --allow=MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC
        # Exits non-zero if disallowed licenses found
```

### Install dependencies with frozen lockfile

```yaml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Install dependencies
        run: ./git-pkgs install --frozen
        # Fails if lockfile is out of sync with manifest

      - name: Run tests
        run: ./run-tests.sh
```

### Generate SBOM on release

```yaml
name: Release
on:
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Generate CycloneDX SBOM
        run: ./git-pkgs sbom --stateless --name=${{ github.repository }} > sbom.json

      - name: Upload SBOM to release
        uses: softprops/action-gh-release@v1
        with:
          files: sbom.json
```

## GitLab CI

### Dependency diff in merge requests

```yaml
dependency-diff:
  stage: test
  script:
    - curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
    - chmod +x git-pkgs
    - ./git-pkgs diff --from=origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --to=HEAD --stateless
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Vulnerability scanning

```yaml
vuln-scan:
  stage: test
  script:
    - curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
    - chmod +x git-pkgs
    - ./git-pkgs vulns --stateless -f json > gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

## Automated dependency updates

Create a scheduled workflow that checks for updates and opens PRs:

```yaml
name: Dependency Updates
on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9am
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Setup Node (for npm)
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Check for updates
        id: outdated
        run: |
          ./git-pkgs outdated --stateless -f json > outdated.json
          if [ -s outdated.json ] && [ "$(cat outdated.json)" != "[]" ]; then
            echo "has_updates=true" >> $GITHUB_OUTPUT
          fi

      - name: Update dependencies
        if: steps.outdated.outputs.has_updates == 'true'
        run: ./git-pkgs update

      - name: Create PR
        if: steps.outdated.outputs.has_updates == 'true'
        uses: peter-evans/create-pull-request@v5
        with:
          commit-message: "Update dependencies"
          title: "chore: update dependencies"
          body: |
            Automated dependency updates.

            ```
            $(./git-pkgs diff HEAD~1 --stateless)
            ```
          branch: deps/automated-updates
```

## Multi-ecosystem monorepo

For projects with multiple package managers:

```yaml
name: CI
on: [push, pull_request]

jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install git-pkgs
        run: |
          curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
          chmod +x git-pkgs

      - name: Setup runtimes
        run: |
          # Setup whatever runtimes your project needs
          # git-pkgs will detect and use the right package managers

      - name: Install all dependencies
        run: ./git-pkgs install --frozen
        # Runs bundle install --frozen AND npm ci (or whatever managers are detected)
```

Or install ecosystems separately:

```yaml
      - name: Install Ruby dependencies
        run: ./git-pkgs install --frozen -e rubygems

      - name: Install JS dependencies
        run: ./git-pkgs install --frozen -e npm
```

## Caching

Cache the git-pkgs binary to speed up workflows:

```yaml
      - name: Cache git-pkgs
        uses: actions/cache@v4
        with:
          path: ./git-pkgs
          key: git-pkgs-${{ runner.os }}

      - name: Install git-pkgs
        run: |
          if [ ! -f ./git-pkgs ]; then
            curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o git-pkgs
            chmod +x git-pkgs
          fi
```

## Docker

Use git-pkgs in a Dockerfile:

```dockerfile
FROM golang:1.21 as builder
RUN curl -sL https://github.com/git-pkgs/git-pkgs/releases/latest/download/git-pkgs-linux-amd64 -o /usr/local/bin/git-pkgs \
    && chmod +x /usr/local/bin/git-pkgs

FROM node:20
COPY --from=builder /usr/local/bin/git-pkgs /usr/local/bin/
WORKDIR /app
COPY package*.json ./
RUN git-pkgs install --frozen
COPY . .
```

## Exit codes

git-pkgs commands use standard exit codes for CI integration:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error or findings (vulns found, license violations, etc.) |

Commands that find issues (vulns, license checks) exit non-zero, making them suitable as quality gates.
