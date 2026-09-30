# Changelog

All notable changes to this fork of [monoxgas/Koppeling](https://github.com/monoxgas/Koppeling) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **NetClone** — architecture-mismatch guard (PE32 ↔ PE32+), automatic timestamp normalization to the reference, automatic Certificate DataDirectory zeroing, and a `-v` / `--verbose` flag listing each cloned entry with its ordinal and forwarder target. Matches PyClone-lief's low-cost safety and OpSec behaviors. PDB stripping, Authenticode overlay stripping, `--copy-resources`, and forwarder-chain detection remain PyClone-lief-only for now.

### Changed

- README **Example** section expanded: side-by-side conversion commands for NetClone, PyClone-pefile, and PyClone-lief; explanation of `-p` / `--reference-path`; shared safety/OpSec features called out separately from PyClone-lief-only ones.

## [0.1.0] - 2026-09-30

First versioned release of the fork.

### Added

- **`PyClone-lief.py`** — new PyClone backend built on [lief](https://lief.re/) 1.0 (Quarkslab), using only lief's documented public API.
- **`PyClone/requirements.txt`** — pins `pefile==2024.8.26` and floors `lief>=1.0.0`.
- PyClone-lief safety and OpSec features:
  - PE32 ↔ PE32+ **architecture mismatch guard**.
  - **Forwarder-chain notice** when the reference has its own forwarded exports.
  - **`--verbose` / `-v`** — prints each cloned entry and its forwarder target.
  - **Automatic PDB path strip** (`target.clear_debug()`) — removes CodeView / attribution leaks.
  - **Timestamp normalization** to the reference's PE header value.
  - **Certificate DataDirectory clear + Authenticode overlay strip** — output reads cleanly as unsigned rather than "signed but broken".
  - **`--copy-resources`** — optional; grafts icon, version info, and manifest from the reference so the Properties dialog matches.
- README **Setup section** covering `pip install -r PyClone/requirements.txt` and choosing the PyClone backend.
- README **PyClone-lief extras** subsection listing the safety and OpSec features.

### Changed

- **`PyClone.py` → `PyClone-pefile.py`** — renamed to make the backend choice explicit. A runtime version guard hard-exits if the loaded `pefile` isn't the pinned version, since the script relies on pefile's private API surface which upstream is actively refactoring.
- **Theif `Dyn-PyClone` build config** now invokes `PyClone-pefile.py` instead of `PyClone.py`.
- **PlatformToolset v142 → v143** across Functions, Harness, and Theif (VS 2022).

### Fixed

- **NetClone and PyClone Name-RVA bug** — the DLL name pointer in the cloned export directory was not shifted by the section delta, causing dumpbin crashes and garbage DLL name reporting on the output.
- **NetClone ordinal ordering** — now iterates exports by ordinal (matches PyClone's existing behavior).
- **NetClone hollow-slot handling** — now skips zero-RVA function slots correctly, matching PyClone and preventing index-out-of-range on DLLs with gaps.
- **PyClone-pefile `bytes()` wrap** in `set_bytes_at_rva` — fixes a real bug where modern pefile rejects the `bytearray` produced by upstream in-place mutation.
- Earlier fork commits carried forward: ordinal encoding, `.dll` extension stripping (fixes lookup-failure crashes on Windows 2008 / Windows 7 hosts).

---

## Maintaining this file

When you make a notable change, add an entry under `[Unreleased]` in the appropriate subsection: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security`.

When cutting a release:

1. Rename the `## [Unreleased]` heading to `## [X.Y.Z] - YYYY-MM-DD` (today's date).
2. Add a fresh `## [Unreleased]` (with `_No changes yet._`) back at the top of the log.
3. Update the comparison links at the bottom of this file:
   - The `[Unreleased]` link becomes `compare/vX.Y.Z...HEAD`.
   - Add a new `[X.Y.Z]` link: `compare/v<previous>...vX.Y.Z` (or `releases/tag/vX.Y.Z` for the very first release).
4. Commit the CHANGELOG changes, then tag, push, and create the GitHub release:

    ```bash
    git tag -a vX.Y.Z -m "vX.Y.Z - <one-line summary>" HEAD
    git push origin vX.Y.Z
    gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <notes-file>
    ```

Version bump rules (per SemVer):

- **PATCH** (`X.Y.z`): bug fixes, doc updates, dependency pins.
- **MINOR** (`X.y.0`): new backend / new flags / new build config, backwards compatible.
- **MAJOR** (`x.0.0`): breaking CLI change, removed backend, incompatible build config.

[Unreleased]: https://github.com/watson0x90/Koppeling/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/watson0x90/Koppeling/releases/tag/v0.1.0
