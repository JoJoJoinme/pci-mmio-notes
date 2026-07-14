#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_file="$script_dir/optionrom/efi-marker.c"
output="${EFI_ROM_OUTPUT:-/root/vm/esxi8-mf/optionrom/808610d3.efirom}"
efirom="${EFIROM_TOOL:-/root/src/ipxe-optionrom-lab/src/util/efirom}"
cc="${CC:-gcc}"
ld="${LD:-ld}"
objcopy="${OBJCOPY:-objcopy}"

for path in "$source_file" /usr/lib/crt0-efi-x86_64.o \
    /usr/lib/elf_x86_64_efi.lds "$efirom"; do
    if [[ ! -e "$path" ]]; then
        echo "missing build dependency: $path" >&2
        exit 2
    fi
done

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
mkdir -p "$(dirname "$output")"

"$cc" \
    -I/usr/include/efi \
    -I/usr/include/efi/x86_64 \
    -I/usr/include/efi/protocol \
    -fpic -ffreestanding -fno-stack-protector -fno-stack-check \
    -fshort-wchar -mno-red-zone -maccumulate-outgoing-args \
    -Wall -Wextra -Werror \
    -c "$source_file" -o "$build_dir/efi-marker.o"

"$ld" \
    -nostdlib -znocombreloc \
    -T /usr/lib/elf_x86_64_efi.lds \
    -shared -Bsymbolic \
    /usr/lib/crt0-efi-x86_64.o "$build_dir/efi-marker.o" \
    -L/usr/lib -lefi -lgnuefi \
    -o "$build_dir/efi-marker.so"

"$objcopy" \
    -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
    -j .rel -j .rela -j .reloc \
    --target=efi-bsdrv-x86_64 \
    "$build_dir/efi-marker.so" "$build_dir/efi-marker.efi"

efirom_args=(--vendor=0x8086 --device=0x10d3)
if [[ "${EFI_ROM_COMPRESS:-0}" == 1 ]]; then
    efirom_args+=(--compress)
fi
"$efirom" "${efirom_args[@]}" \
    "$build_dir/efi-marker.efi" "$output"

if [[ "${EFI_ROM_COMPRESS:-0}" == 1 && \
      "${EFI_ROM_PAD_TO_DECOMPRESSED:-0}" == 1 ]]; then
    compact="$build_dir/efi-marker.compact.efirom"
    mv "$output" "$compact"
    python3 "$script_dir/optionrom/pad-compressed-efirom.py" \
        "$compact" "$output"
fi

printf 'source=%s\n' "$source_file"
printf 'compressed=%s\n' "${EFI_ROM_COMPRESS:-0}"
printf 'padded_to_decompressed=%s\n' \
    "${EFI_ROM_PAD_TO_DECOMPRESSED:-0}"
sha256sum "$source_file" "$output"
file "$build_dir/efi-marker.efi" "$output"
objdump -x "$build_dir/efi-marker.efi" | \
    grep -E 'Subsystem|AddressOfEntryPoint|ImageBase'
