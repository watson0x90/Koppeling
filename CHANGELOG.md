# Changelog

All notable changes to this fork of [monoxgas/Koppeling](https://github.com/monoxgas/Koppeling) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No changes yet._

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

[Unreleased]: https://github.com/watson0x90/Koppeling/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/watson0x90/Koppeling/releases/tag/v0.1.0
