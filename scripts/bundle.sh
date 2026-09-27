#!/usr/bin/env bash
# Build and verify a self-contained LogsTotal bundle (developer / ops).
#
# `task deploy ARCHIVE=<file>` already installs on a host with no internet — the archive is
# copied from the machine running the deploy, so hosts never reach the release server. What
# it does NOT solve is the images. Every host still runs `docker compose build`, and that
# pulls python:3.14-slim, Debian packages, PyPI wheels and a ~46 MB Tailwind CLI from
# GitHub; compose then pulls Redis, PostgreSQL, Caddy and socat; and Zircolite — which five
# of the six shipped workflows use — is pulled LAZILY INSIDE THE FIRST WINDOWS JOB. So a
# closed-network install passes every check, reports healthy, and fails hours later when
# someone uploads an EVTX file.
#
# A bundle is the release archive plus every image it needs, saved with `docker save`, so
# nothing on the receiving side has to build or pull anything.
#
# It is NOT a release asset, deliberately: it is ~430 MB against the archive's 125 MB, it
# is single-ARCHITECTURE (docker save records one), and most operators never need it. Build
# it where there IS a network, carry it in, install from it.
#
# Usage:
#   bash scripts/bundle.sh build     # from this tree
#   bash scripts/bundle.sh verify <bundle.7z>
#
# Configuration:
#   VERSION          the release to bundle (default: this tree's VERSION)
#   ARCHIVE          use this .7z instead of building one
#   BUNDLE_OUT       output path (default: logstotal-bundle-<version>-<arch>.7z)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# ── What a bundle has to contain ─────────────────────────────────────────────
#
# Read from the files that declare them rather than restated here, because a list of
# images maintained by hand is a list that goes stale silently — and the failure mode is
# an install that looks fine until the one job that needs the missing image.
bundle_images() {
  # Third-party images from both compose files.
  # The `${REGISTRY_PREFIX:-}` a mirrored network substitutes is stripped: a bundle carries
  # the UPSTREAM images, because it is the answer for a network with no registry at all. A
  # site that has a mirror does not need one.
  # shellcheck disable=SC2016  # the greps filter a LITERAL ${…}, not a value to expand
  grep -hoE '^\s+image: \$?\{?[A-Za-z_]*:?-?\}?[a-z0-9./:@-]+' \
    docker-compose.yml docker-compose.worker.yml 2>/dev/null |
    sed -e 's/.*image: //' -e 's/^\${[^}]*}//' |
    grep -v '^logstotal' | grep -v '\${'
  # Tool images from the workflow definitions. Zircolite is pinned by digest, and the
  # digest is what must be saved: a tag can move, and an air-gapped host cannot check.
  grep -hoE 'docker_image:\s*\S+' workflows/*.yml 2>/dev/null | sed 's/docker_image:[[:space:]]*//'
}

# save_ref_for REF — the reference to `docker save`, given the one a workflow names.
#
# A digest-pinned reference cannot survive `docker save`. Measured: the tarball for
# `wagga40/zircolite:3.8.1@sha256:41b0…` records `RepoTags:null`, because a digest is not a
# tag and the save format has nowhere to put it. `docker load` on the far side therefore
# produces a dangling image — `<none>:<none>`, RepoTags=[] AND RepoDigests=[] — and a real
# `docker run` of the workflow's reference goes to the network for a manifest it cannot
# reach. On an air-gapped host that is the Windows path failing hours after a green install.
#
# So the tag is what travels. The PIN IS STILL ENFORCED, just earlier and once: `docker pull`
# above resolves the digest against the registry on a machine that has one, and the bundle
# carries its own sha256 from there. That is the air-gap trade — verify at build rather than
# at run — and docs/air-gapped.md states it rather than leaving it implied.
save_ref_for() {
  printf '%s' "${1%%@sha256:*}"
}

_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'x86_64' ;;
    aarch64 | arm64) printf 'aarch64' ;;
    *) uname -m ;;
  esac
}

do_build() {
  require_cmd docker "A bundle is built by saving images; Docker is how."
  require_cmd 7z "Install p7zip — a bundle is a .7z, like the release archive inside it."

  local version
  version="${VERSION:-$(read_version_file)}"
  if [ -n "${ARCHIVE:-}" ]; then
    version=$(7z x -so "$ARCHIVE" VERSION | sed -n 's/^version:[[:space:]]*//p')
    [ -z "${VERSION:-}" ] || [ "${VERSION#v}" = "$version" ] || die "VERSION differs from the selected archive."
  fi
  [ -n "$version" ] || die "no VERSION here and none given. Set VERSION=X.Y.Z."
  version="${version#v}"

  local arch out
  arch=$(_arch)
  out="${BUNDLE_OUT:-logstotal-bundle-${version}-${arch}.7z}"
  # Absolute, because the archive is written from inside $work — 7z takes its file list
  # relative to the CWD, so the assembly step has to cd there. A relative $out would land
  # in the temp directory and be deleted by the EXIT trap, which is a build that reports
  # success and leaves nothing behind.
  case "$out" in
    /*) ;;
    *) out="$(pwd)/${out}" ;;
  esac

  # Script scope, not `local`: the EXIT trap fires after this function has returned, so a
  # function-local is out of scope by then and `rm -rf "$work"` dies with
  # `work: unbound variable` under set -u — printing a shell error on top of the summary
  # the operator actually needs. deploy-multiserver.sh carries the same note for STAGE_TMPDIR.
  work=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-bundle.XXXXXX")
  trap 'rm -rf "${work:-}"' EXIT
  mkdir -p "${work}/images"

  # ── The application archive ────────────────────────────────────────────────
  header "1/4: the release archive"
  local archive
  if [ -n "${ARCHIVE:-}" ]; then
    [ -f "$ARCHIVE" ] || die "ARCHIVE not found: ${ARCHIVE}"
    archive="$ARCHIVE"
    info "using ${archive}"
  else
    archive="$(pwd)/$(package_basename "$version")"
    if [ -f "$archive" ]; then
      info "using ${archive}"
    else
      info "building it"
      lt_task package
      [ -f "$archive" ] || die "./logstotal package did not produce ${archive}"
    fi
  fi
  cp "$archive" "${work}/$(basename "$archive")"
  local source_tree archive_hash
  source_tree="${work}/source"
  mkdir -p "$source_tree"
  7z x -y -o"$source_tree" "$archive" >/dev/null
  [ "$(read_version_file "$source_tree")" = "$version" ] || die "Archive VERSION differs from the bundle version."
  for required in Dockerfile Dockerfile.garage docker-compose.yml docker-compose.worker.yml; do
    [ -f "$source_tree/$required" ] || die "The release archive is missing $required."
  done
  archive_hash=$(file_sha256 "$archive")

  # ── The images WE build ────────────────────────────────────────────────────
  header "2/4: the images built here"
  # Tagged with the RELEASE rather than `latest`, so a host can hold two and a rollback has
  # something to go back to. deploy-multiserver.sh exports LOGSTOTAL_IMAGE_TAG so compose
  # asks for this tag.
  #
  # BOTH of them. `garage` is built from Dockerfile.garage exactly as the app is from
  # Dockerfile, and bundling only the app would give an air-gapped deploy that runs to its
  # last step and dies on
  #     Error response from daemon: No such image: logstotal-garage:latest
  # — the control plane never starting. It is in the `s3` profile, which every multi-server
  # install turns on, so this is the default path and not a corner.
  local app_tag="logstotal:${version}"
  info "docker build -t ${app_tag}"
  (cd "$source_tree" && docker build --label "org.logstotal.archive-sha256=$archive_hash" --label "org.opencontainers.image.version=$version" -t "$app_tag" .)
  info "docker save ${app_tag}"
  docker save "$app_tag" -o "${work}/images/logstotal.tar"

  local garage_tag="logstotal-garage:${version}"
  info "docker build -t ${garage_tag}"
  (cd "$source_tree" && docker build --label "org.logstotal.archive-sha256=$archive_hash" --label "org.opencontainers.image.version=$version" -f Dockerfile.garage -t "$garage_tag" .)
  info "docker save ${garage_tag}"
  docker save "$garage_tag" -o "${work}/images/logstotal-garage.tar"

  # ── Everything else it needs ───────────────────────────────────────────────
  header "3/4: the images it pulls at runtime"
  local manifest_images=() image saved i=0
  while IFS= read -r image; do
    [ -n "$image" ] || continue
    info "docker pull ${image}"
    docker pull "$image" >/dev/null
    i=$((i + 1))

    # SAVE THE TAG, NOT THE DIGEST — see save_ref_for. The pull above is where the pin is
    # enforced; what travels is the tag, because a digest cannot survive the trip.
    saved=$(save_ref_for "$image")
    if [ "$saved" != "$image" ]; then
      info "docker tag ${saved}  (the digest cannot survive docker save)"
      docker tag "$image" "$saved"
    fi
    docker save "$saved" -o "${work}/images/third-party-${i}.tar"
    manifest_images+=("$saved")
  done < <((cd "$source_tree" && bundle_images) | sort -u)

  # A bundle with no runtime images is the precise failure this whole thing exists to
  # prevent — an install that passes every check and then cannot analyse a Windows log.
  # The list is read from docker-compose.yml and workflows/, so an empty one means this is
  # not being run from the repo root, and the honest response is to refuse.
  if [ "${#manifest_images[@]}" -eq 0 ]; then
    die "found no runtime images to bundle.
       They are read from docker-compose.yml and workflows/*.yml — run this from the repo
       root. A bundle without them installs cleanly and then cannot analyse a Windows log,
       which is the failure it exists to prevent."
  fi

  rm -rf "$source_tree"

  # ── The manifest, then the tar ─────────────────────────────────────────────
  header "4/4: manifest and assembly"
  {
    printf '{\n'
    printf '  "schema": 2,\n'
    printf '  "version": "%s",\n' "$version"
    printf '  "architecture": "%s",\n' "$arch"
    printf '  "archive": "%s",\n' "$(basename "$archive")"
    printf '  "archive_sha256": "%s",\n' "$(file_sha256 "$archive")"
    printf '  "app_image": "%s",\n' "$app_tag"
    printf '  "garage_image": "%s",\n' "$garage_tag"
    printf '  "image_tag": "%s",\n' "$version"
    printf '  "images": [\n'
    local n=${#manifest_images[@]} idx=0
    for image in "${manifest_images[@]}"; do
      idx=$((idx + 1))
      if [ "$idx" -lt "$n" ]; then printf '    "%s",\n' "$image"; else printf '    "%s"\n' "$image"; fi
    done
    printf '  ]\n'
    printf '}\n'
  } > "${work}/bundle-manifest.json"

  # The same flags package.sh uses, deliberately: one archive format and one set of options
  # across both artifacts, so there is a single thing to reason about. `7z` is already a hard
  # prerequisite on every host — deploy:bootstrap installs it and extracting the release
  # needs it — so this asks for nothing new.
  #
  # -mf=off IS LOAD-BEARING and is why these flags are copied rather than invented. 7-Zip 21+
  # applies an ARM64 BCJ filter (method 0A) that p7zip cannot decode: it exits 2 having
  # extracted everything except the executables. The bundle carries image tarballs full of
  # binaries, so it is exactly as exposed as the release archive. verify-artifacts.sh gates
  # the archive on it; do_verify below gates this.
  #
  # 7z also avoids tar's macOS trap: bsdtar writes an AppleDouble `._name` sidecar beside
  # every file, junk on Linux and double the entries any consumer counts.
  #
  # Measured on a real 447 MB bundle: tar 468,446,208 bytes; -mx=9 455,269,808 in 26s. The
  # gain is small because docker layers arrive pre-compressed — the reason to do this is the
  # single format, and 26s is noise beside the image builds and saves above it.
  ( cd "$work" && 7z a -mx=9 -mmt=on -ms=on -mf=off "$out" . >/dev/null )
  local size
  size=$(du -h "$out" | cut -f1)
  printf '%s  %s\n' "$(file_sha256 "$out")" "$(basename "$out")" > "${out}.sha256"

  printf '\n'
  info "Bundle: ${out} (${size})"
  info "        ${out}.sha256"
  printf '\n'
  printf '  It carries %s, the application image, and %d more.\n' "$(basename "$archive")" "${#manifest_images[@]}"
  printf '  Architecture: %s — docker save records ONE, so this installs on %s hosts only.\n' "$arch" "$arch"
  printf '\n'
  printf '  Carry it across, then:\n'
  printf '    ./logstotal deploy  BUNDLE=/media/usb/%s\n' "$(basename "$out")"
  printf '    ./logstotal upgrade BUNDLE=/media/usb/%s\n' "$(basename "$out")"
  printf '\n'
}

# do_verify — check a bundle WITHOUT Docker.
#
# The point of the constraint: an operator has to be able to check a bundle before carrying
# it through an airlock, and the machine they check it on is not necessarily one that runs
# containers. So this reads the tar and the manifest, and nothing else.
do_verify() {
  local bundle="${1:-}"
  [ -n "$bundle" ] || die "which bundle? bash scripts/bundle.sh verify <bundle.7z>"
  [ -f "$bundle" ] || die "not found: ${bundle}"
  require_cmd 7z "Install p7zip — a bundle is a .7z."

  if [ -f "${bundle}.sha256" ]; then
    local want got
    want=$(cut -d' ' -f1 < "${bundle}.sha256")
    got=$(file_sha256 "$bundle")
    if [ "$want" = "$got" ]; then
      v_pass "checksum matches ${bundle}.sha256"
    else
      v_fail "checksum MISMATCH" "expected ${want}" "got      ${got}"
    fi
  else
    # Not a failure: a checksum file is only as trustworthy as the channel it arrived on,
    # and saying "verified" about a file that carried its own checksum would overstate it.
    v_unknown "no ${bundle}.sha256 beside it — nothing to check the transfer against."
  fi

  # Script scope, for the reason in do_build.
  work=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-verify.XXXXXX")
  trap 'rm -rf "${work:-}"' EXIT
  7z x -y -o"$work" "$bundle" bundle-manifest.json >/dev/null 2>&1 ||
    die "no bundle-manifest.json inside — is this a LogsTotal bundle?"
  [ -f "${work}/bundle-manifest.json" ] ||
    die "no bundle-manifest.json inside — is this a LogsTotal bundle?"

  local manifest="${work}/bundle-manifest.json"
  local version arch archive
  version=$(run_py -c "import json,sys;print(json.load(open(sys.argv[1]))['version'])" "$manifest")
  arch=$(run_py -c "import json,sys;print(json.load(open(sys.argv[1]))['architecture'])" "$manifest")
  archive=$(run_py -c "import json,sys;print(json.load(open(sys.argv[1]))['archive'])" "$manifest")

  printf '\n  version      %s\n' "$version"
  printf '  architecture %s\n' "$arch"
  printf '  archive      %s\n' "$archive"

  local listed
  # -slt and the `Path = ` prefix rather than the default listing's columns: a name is the
  # LAST field there, so a path containing a space would be truncated by any awk that reads
  # it. Nothing in a bundle has one today; this costs nothing and cannot be got wrong later.
  listed=$(7z l -ba -slt "$bundle" | sed -n 's/^Path = //p')
  # if/then, not `A && B || C`: that runs C whenever B fails too, so a verdict helper
  # returning non-zero would report both outcomes for one check.
  if echo "$listed" | grep -q "$archive"; then
    v_pass "the release archive is inside"
  else
    v_fail "the manifest names ${archive} and the bundle does not contain it"
  fi
  if echo "$listed" | grep -q 'images/logstotal.tar'; then
    v_pass "the application image is inside"
  else
    v_fail "no application image — every host would have to build one"
  fi
  # Checked separately, because a bundle missing ONLY this one would pass every other check
  # and then fail the deploy at its last step with `No such image: logstotal-garage:latest`.
  if echo "$listed" | grep -q 'images/logstotal-garage.tar'; then
    v_pass "the garage (S3) image is inside"
  else
    v_fail "no garage image — the control plane cannot start with the s3 profile on"
  fi

  local want_images have_images
  want_images=$(run_py -c "import json,sys;print(len(json.load(open(sys.argv[1]))['images']))" "$manifest")
  have_images=$(echo "$listed" | grep -c 'images/third-party-' || true)
  if [ "$want_images" = "$have_images" ]; then
    v_pass "${have_images} runtime image(s) present, as the manifest says"
  else
    v_fail "the manifest names ${want_images} runtime images; ${have_images} are inside"
  fi

  local here
  here=$(_arch)
  if [ "$arch" = "$here" ]; then
    v_pass "architecture matches this machine"
  else
    # UNKNOWN rather than FAIL: this is usually not the machine it will be installed on.
    v_unknown "built for ${arch}; this machine is ${here}." \
      "Fine if the target hosts are ${arch}. docker save records one architecture."
  fi

  if run_py "$SCRIPT_DIR/bundle_manifest.py" verify "$bundle"; then
    v_pass "embedded release and image provenance agree"
  else
    v_fail "bundle contents do not match their manifest"
  fi

  printf '\n'
  v_tally; printf '\n'
  exit "$(v_status)"
}

case "${1:-build}" in
  build) shift || true; do_build "$@" ;;
  verify) shift || true; do_verify "$@" ;;
  *) die "Unknown action: ${1}. Use: build | verify <bundle.7z>" ;;
esac
