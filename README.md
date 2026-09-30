# Koppeling
This project is a demonstration of advanced DLL hijack techniques. It was released in conjunction with the "[Adaptive DLL Hijacking](https://silentbreaksecurity.com/adaptive-dll-hijacking/)" blog post. I recommend you start there to contextualize this code.

This project is comprised of the following elements:
- **Harness.exe:** The "victim" application which is vulnerable to hijacking (static/dynamic)
- **Functions.dll:** The "real" library which exposes valid functionality to the harness
- **Theif.dll:** The "evil" library which is attempting to gain execution
- **NetClone.exe:** A C# application which will clone exports from one DLL to another
- **PyClone-pefile.py / PyClone-lief.py:** Python 3 scripts which mimic NetClone functionality, backed by [`pefile`](https://github.com/erocarrera/pefile) or [`lief`](https://lief.re/) respectively — pick whichever backend suits your workflow (see `PyClone/requirements.txt`)

The VS solution itself supports 4 build configurations which map to 4 different methods of proxying functionality. This should provide a nice scalable way of demonstrating more techniques in the future.
- **Stc-Forward:** Forwards export names during the build process using linker comments
- **Dyn-NetClone:** Clones the export table from *functions.dll* onto *theif.dll* post-build using NetClone
- **Dyn-PyClone:** Clones the export table from *functions.dll* onto *theif.dll* post-build using PyClone
- **Dyn-Rebuild:** Rebuilds the export table and patches linked import tables post-load to dynamically prepare for function proxying

The goal of each technique is to successfully capture code execution while proxying functionality to the legitimate DLL. Each technique is tested to ensure static and dynamic sink situations are handled. This is by far not every primitive or technique variation. The post above goes into more detail.

## Setup

The C# and C++ projects build straight out of the Visual Studio solution (`Koppeling.sln`).

The Python cloners have external dependencies:

```
pip install -r PyClone/requirements.txt
```

That file pins `pefile` to the version `PyClone-pefile.py` has been verified against (the script reaches into pefile's private API and asserts the pinned version at startup), and floors `lief` at the 1.0 stable-API release used by `PyClone-lief.py`. You only need the backend you plan to use, but installing both is harmless.

The `Dyn-PyClone` build configuration invokes `PyClone-pefile.py` by default; if you'd rather use the lief backend, edit the post-build command in `Theif/Theif.vcxproj` to point at `PyClone-lief.py` instead.

### PyClone-lief extras

`PyClone-lief.py` matches the pefile version's core export-cloning behavior and adds a handful of safety and OpSec touches automatically:

- Rejects `x86 ↔ x64` mismatches between target and reference (both cloners previously produced silently corrupt output on mismatch)
- Prints an info line when the reference has its own forwarded exports, since the clone will chain-forward through them at runtime
- Strips CodeView / PDB path from the target (attribution leak — PDB paths often contain usernames and build directories)
- Copies the reference's timestamp onto the output's PE header
- Zeros the Certificate DataDirectory and drops the Authenticode overlay, so the output reads as cleanly unsigned rather than "signed but broken"

Two optional flags:

- `--verbose` / `-v` — print each cloned entry and its forwarder target
- `--copy-resources` — graft the reference's icon, version info, and manifest onto the target so the right-click Properties dialog matches the legitimate DLL

Run `python PyClone/PyClone-lief.py --help` for the full argument list.

## Example

Prepare a hijack scenario with an obviously incorrect DLL
```
> copy C:\windows\system32\whoami.exe .\whoami.exe
        1 file(s) copied.

> copy C:\windows\system32\kernel32.dll .\wkscli.dll
        1 file(s) copied.

```

Executing in the current configuration should result in an error
```
> whoami.exe 

"Entry Point Not Found"
```

Convert kernel32 to proxy functionality for wkscli. Any of the three cloners work — they produce equivalent export tables. All three commands below graft wkscli's 29 exports onto a copy of kernel32 as forwarders back to the real wkscli.

**NetClone (C#)**
```
> NetClone.exe --target C:\windows\system32\kernel32.dll --reference C:\windows\system32\wkscli.dll --reference-path wkscli --output wkscli.dll
[+] Done.
```

**PyClone-pefile (Python, pefile backend)**
```
> python PyClone\PyClone-pefile.py C:\windows\system32\kernel32.dll C:\windows\system32\wkscli.dll -p wkscli -o wkscli.dll
[+] Loaded files

[+] Done: wkscli.dll
```

**PyClone-lief (Python, lief backend)**
```
> python PyClone\PyClone-lief.py C:\windows\system32\kernel32.dll C:\windows\system32\wkscli.dll -p wkscli -o wkscli.dll
[+] Loaded files

[+] Done: wkscli.dll
```

The `-p wkscli` (`--reference-path wkscli` on NetClone) sets the forwarder-string prefix. If you omit it, the tools use the value passed as `--reference` verbatim, so absolute paths end up embedded in the export table as awkward forwarders like `C:\windows\system32\wkscli.NetAddAlternateComputerName` instead of `wkscli.NetAddAlternateComputerName`.

All three cloners include the same automatic safety and OpSec behaviors:

- **Architecture mismatch guard** — rejects PE32 ↔ PE32+ mismatches instead of producing silently corrupt output
- **Timestamp normalization** — matches the reference's PE header timestamp on the output
- **Certificate DataDirectory clear** — zeros the security data directory so the output reads as unsigned rather than "signed but broken"

All three also accept `-v` / `--verbose` for per-entry output. PyClone-lief goes further and adds several more OpSec features on top; see below.

With the converted DLL in place, `whoami.exe` now finds a usable `wkscli`:
```
> whoami.exe
COMPUTER\User
```

### Verbose output

`-v` / `--verbose` is available on all three cloners. Example with PyClone-lief:
```
> python PyClone\PyClone-lief.py C:\windows\system32\kernel32.dll C:\windows\system32\wkscli.dll -p wkscli -o wkscli.dll -v
[+] Loaded files
[i] Cloned 29 entries:
    ord=1     NetAddAlternateComputerName              -> wkscli.NetAddAlternateComputerName
    ord=2     NetEnumerateComputerNames                -> wkscli.NetEnumerateComputerNames
    ord=3     NetGetJoinInformation                    -> wkscli.NetGetJoinInformation
    ... (26 more)

[+] Done: wkscli.dll
```

NetClone's verbose output is slightly simpler (ordinal → forwarder only, no separate short-name column) but conveys the same information.

### Architecture-mismatch guard

All three cloners fail cleanly on PE32 ↔ PE32+ mismatch instead of producing corrupt output:
```
> python PyClone\PyClone-lief.py C:\Windows\SysWOW64\wkscli.dll C:\Windows\System32\kernel32.dll -p kernel32
[+] Loaded files
[!] Architecture mismatch: target is PE32, reference is PE32_PLUS
```

NetClone throws an equivalent exception on the same input (`Architecture mismatch: target magic 0x010B, reference magic 0x020B`).

### PyClone-lief only

Beyond the shared features above, PyClone-lief also:

- **Strips the CodeView / PDB path** from the target automatically (removes attribution leaks)
- **Strips the Authenticode overlay** so the stale signature bytes past the last section don't ship with the output
- **`--copy-resources`** — grafts the reference's icon, version info, and manifest onto the target so Explorer's Properties dialog matches the legitimate DLL:
    ```
    > python PyClone\PyClone-lief.py C:\windows\system32\kernel32.dll C:\windows\system32\wkscli.dll -p wkscli -o wkscli.dll --copy-resources
    ```
    After this, right-clicking `wkscli.dll` and choosing Properties shows `FileDescription = "Workstation Service Client DLL"` and `OriginalFilename = "WKSCLI.DLL"` instead of kernel32's version metadata.

- **Chain-forward notice** — when the reference has its own forwarded exports, PyClone-lief flags this on stderr:
    ```
    > python PyClone\PyClone-lief.py C:\windows\system32\wkscli.dll C:\windows\system32\kernel32.dll -p kernel32 -o kernel32.dll
    [+] Loaded files
    [i] Reference has 211 existing forwarder(s); cloned exports will chain through them at runtime.

    [+] Done: kernel32.dll
    ```

NetClone doesn't currently detect these situations; it silently produces the output. If any of the above features matter for your workflow, use PyClone-lief.

Run `python PyClone\PyClone-lief.py --help` (or `python PyClone\PyClone-pefile.py --help`, or `NetClone.exe --help`) for the full argument list.