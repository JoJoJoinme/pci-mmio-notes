#!/usr/bin/env bash
set -o pipefail

stage_dir="${VCSA_STAGE_DIR:-/mnt/codex-stage}"
install_media="${VCSA_INSTALL_MEDIA:-/dev/sdb}"

mkdir -p "$stage_dir"
if ! mountpoint -q "$stage_dir"; then
  mount -o ro "$install_media" "$stage_dir"
fi

test -x "$stage_dir/install.sh"
test -r "$stage_dir/common-install.sh"

cd "$stage_dir"

for package in VMware-vc-support applmgmt vc-deploy; do
  rpm -q "$package" >/dev/null || {
    echo "required core package is missing: $package" >&2
    exit 2
  }
done

if [[ -e /var/log/firstboot/deferred ]]; then
  echo "Stage 1 is already deferred; refusing to rerun configure." >&2
  exit 3
fi

source ./common-install.sh
current_state="$(/usr/bin/python3 -c \
  'import json; print(json.load(open("/etc/vmware/deploy/state.json"))["state"])')"
if [[ "$current_state" == "failed" ]]; then
  if ! grep -q 'Failed to install VMware-vc-support' "$rpmInstallStatus" && \
     ! grep -q 'Failed to install VMware-containerfw' "$rpmInstallStatus"; then
    echo "refusing an unrelated failed deployment state" >&2
    exit 4
  fi
elif [[ "$current_state" != "not_initialized" ]]; then
  echo "unexpected deployment state: $current_state" >&2
  exit 4
fi

rpm_count=0
rpm_skip_count=0
vc_desired_state="$(get_vc_desired_state)"
while IFS= read -r rpm_file; do
  [[ -n "$rpm_file" ]] || continue
  media_path="$stage_dir/$rpm_file"
  package_name="$(rpm -qp --qf '%{NAME}' "$media_path")" || exit 6
  media_nevra="$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$media_path")" || exit 6
  installed_nevras="$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$package_name" 2>/dev/null || true)"
  if grep -Fxq "$media_nevra" <<<"$installed_nevras"; then
    ((rpm_count += 1))
    continue
  fi

  skip_reason=""
  for core_name in "${core_rpm_list[@]}"; do
    if [[ "$rpm_file" =~ $core_name ]]; then
      skip_reason="core RPM"
      break
    fi
  done
  if [[ -z "$skip_reason" ]] && ! /bin/rpm-fsschecker "$rpm_file" >/dev/null 2>&1; then
    skip_reason="feature state"
  fi
  if [[ -z "$skip_reason" ]] && \
     ! /bin/service_install_util.py "$rpm_file" "$vc_desired_state" >/dev/null 2>&1; then
    skip_reason="desired state"
  fi
  if [[ -z "$skip_reason" ]]; then
    echo "media RPM is neither installed nor skipped by official policy: $media_nevra" >&2
    exit 6
  fi
  echo "Verified official skip ($skip_reason): $media_nevra"
  ((rpm_skip_count += 1))
done < "$stage_dir/install_embedded.lst"
echo "Verified $rpm_count installed and $rpm_skip_count policy-skipped media RPMs."

install_rpms() {
  set_status "rpminstall"
  set_progress "running" "Verified existing RPMs" "$rpmInstallStatus" 50
  echo "$(date): Skipping RPM reinstall after exact media NEVRA verification." | tee -a "$cloudvmlog"
}

if [[ "${1:-}" == "--verify-only" ]]; then
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -e "$rpmInstallStatus" ]]; then
  mv "$rpmInstallStatus" "${rpmInstallStatus}.before-resume-${stamp}"
fi
rm -f /var/log/firstboot/failed

prune_sensitive_param="False"
trap exit_cleanup EXIT

init_deploy_logging
log_start "main_func"
set_rpm_install_phase_start
log_time configure

checkAutoConfig
if ! echo "$autoConfig" | grep -qi '^true$'; then
  touch "$installationDeferred"
  updateDeploymentType
  set_vcsa_deploy_state "initialized"
  log_end "main_func"
  exit 0
fi

echo "deployment.autoconfig unexpectedly requested Stage 2" >&2
exit 5
