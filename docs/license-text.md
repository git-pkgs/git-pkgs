# Package License Text

`git pkgs licenses` normally reports identifiers from package and version metadata. The `--license-text` option also downloads the selected package archives, scans their contents with [git-pkgs/licenses](https://github.com/git-pkgs/licenses), and adds decoded license text, notice text, and manifest declarations to JSON output.

```bash
git pkgs licenses --license-text --format json
```

No package manager command or dependency installation is required. The option works with the current dependency state, `--commit`, and `--branch`. It requires JSON output and cannot be combined with `--drift`.

## Dependency Selection

The `--dependencies` option controls both the metadata report and archive scans. It cannot be combined with `--drift`.

- `direct` includes dependencies declared in manifests and resolved lockfile entries marked as direct. This is the default.
- `indirect` includes resolved lockfile entries that were not selected as direct dependencies.
- `all` includes both sets.

Direct declarations are matched to resolved instances from lockfiles in the same manifest directory. Package URL and version distinguish separate instances, so two indirect versions of one package remain separate results. `--license-text` requires a resolved version for every selected dependency. A project with manifests but no resolved lockfile data can still use the metadata-only report, but it cannot request archive text.

```bash
git pkgs licenses --license-text --format json --dependencies indirect
git pkgs licenses --license-text --format json --dependencies all
```

## Artifact Handling

Each archive request contains a canonical versioned package URL and any supported digest recorded in the lockfile. [git-pkgs/registries](https://github.com/git-pkgs/registries) resolves the registry download URL. When a version publishes several files, a lockfile digest selects the matching file. If no usable digest is available, the registry's default file is used.

[git-pkgs/artifacts](https://github.com/git-pkgs/artifacts) coordinates cache lookup, download, integrity verification, and publication. A lockfile digest takes precedence over a digest returned by the registry. Downloads are written to a private staging path, verified before publication, and stored with a computed SHA-256 digest. Corrupt cache entries cause an error.

[git-pkgs/archives](https://github.com/git-pkgs/archives) opens the verified file and extracts it to a temporary directory. Archive formats are selected from the registry filename when possible. Its [git-pkgs/magic](https://github.com/git-pkgs/magic) integration detects ZIP, TAR, gzip, bzip2, xz, and zstd content when the filename has no recognised archive extension. The extracted files are then scanned by `git-pkgs/licenses`.

The scanner reads package manifests and legal files such as `LICENSE`, `COPYING`, and `NOTICE`. If it finds a root license expression, `licenses` contains the scanned expression and `license_source` is `"scan"`. Package or version metadata remains the source when the archive supplies text without an expression. Results from several locked files for the same versioned package URL are merged.

## JSON Fields

The additional fields are omitted when they have no value:

- `license_text` contains decoded text from license files.
- `notice_text` contains decoded text from notice files.
- `declared` contains license declarations read from package manifests. Each record includes its path, raw values, referenced license file, and normalized SPDX expression when available.

```json
[
  {
    "name": "example",
    "ecosystem": "npm",
    "version": "1.2.3",
    "licenses": ["MIT"],
    "license_text": "MIT License\n\n...",
    "notice_text": "Copyright Example Authors\n",
    "declared": [
      {
        "path": "package.json",
        "raw": ["MIT"],
        "license_file": "",
        "normalized_expression": "MIT"
      }
    ],
    "manifest_path": "package.json",
    "purl": "pkg:npm/example@1.2.3",
    "license_source": "scan"
  }
]
```

## Cache and Limits

Archives are cached below the operating system's user cache directory at `git-pkgs/artifacts`. `--offline` reads this cache and makes no registry or package download requests. Package metadata must also be present in the git-pkgs database. An offline cache miss stops the command. There is currently no command that only downloads or preloads the archive cache, and the cache layout is an internal detail. When the cached artifact bytes exceed 4 GiB at command start, the oldest entries are removed until the total is under that limit.

The compressed file limit is 512 MiB. Extracted contents are limited to 512 MiB and 100,000 archive entries per package. The license scanner also limits directory depth to 32, visited files to 10,000, and individual files to 1 MiB. Binary files, symlinks, and oversized files are skipped. A skipped file with a legal filename, or reaching the file-count limit, produces an error instead of a partial attribution report.

Artifact resolution requires a registry supported by `git-pkgs/registries` and an available package download. A lockfile may contain hashes for several platform-specific files while its parsed dependency record retains one hash. In that case the scan covers the selected archive rather than every file published for that version. Registry authentication is not configured by this command.
