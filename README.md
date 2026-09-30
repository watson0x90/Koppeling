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

Convert kernel32 to proxy functionality for wkscli
```
> NetClone.exe --target C:\windows\system32\kernel32.dll --reference C:\windows\system32\wkscli.dll --output wkscli.dll
[+] Done.

> whoami.exe
COMPUTER\User
```