#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_tree=${KERNEL_SOURCE:-/root/src/WSL2-Linux-Kernel-6.6}
worktree=${KERNEL_WORKTREE:-/root/src/WSL2-Linux-Kernel-6.6-acs-provenance-build}
output=${KERNEL_OUTPUT:-/mnt/e/Code/PCI/_artifacts/acs-provenance-kernel}
jobs=${KERNEL_JOBS:-$(nproc)}
resume=${KERNEL_RESUME:-0}
committer_name=${KERNEL_COMMITTER_NAME:-JoJoJoinme}
committer_email=${KERNEL_COMMITTER_EMAIL:-JoJoJoinme@users.noreply.github.com}
patch_file="$script_dir/0001-PCI-expose-ACS-override-provenance.patch"

if [[ ! -d "$source_tree/.git" ]]; then
    printf 'kernel source is not a Git checkout: %s\n' "$source_tree" >&2
    exit 2
fi
if [[ -e "$worktree" && "$resume" != 1 ]]; then
    printf 'refusing to reuse existing worktree: %s\n' "$worktree" >&2
    printf 'set KERNEL_RESUME=1 to continue an interrupted build\n' >&2
    exit 2
fi
if [[ ! -f "$patch_file" ]]; then
    printf 'missing patch: %s\n' "$patch_file" >&2
    exit 2
fi

mkdir -p "$output"
if [[ ! -e "$worktree" ]]; then
    base_commit=$(git -C "$source_tree" rev-parse HEAD)
    git -C "$source_tree" worktree add --detach "$worktree" "$base_commit"
    git -C "$worktree" apply --check "$patch_file"
    GIT_COMMITTER_NAME="$committer_name" GIT_COMMITTER_EMAIL="$committer_email" \
        git -C "$worktree" am "$patch_file"

    if [[ -f "$source_tree/.config" ]]; then
        cp "$source_tree/.config" "$worktree/.config"
    else
        cp "$worktree/Microsoft/config-wsl" "$worktree/.config"
    fi
elif [[ ! -f "$worktree/.config" ]]; then
    printf 'resume worktree has no .config: %s\n' "$worktree" >&2
    exit 2
fi

make -C "$worktree" olddefconfig
make -C "$worktree" -j"$jobs" bzImage

image="$output/bzImage-acs-provenance"
cp "$worktree/arch/x86/boot/bzImage" "$image"
git -C "$worktree" rev-parse HEAD > "$output/kernel-commit.txt"
sha256sum "$worktree/.config" > "$output/config.sha256"
sha256sum "$image" > "$output/bzImage.sha256"

printf 'kernel image: %s\n' "$image"
printf 'worktree retained for audit: %s\n' "$worktree"
