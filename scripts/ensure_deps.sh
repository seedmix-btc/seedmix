#!/usr/bin/env bash
# -- Ensure external dependencies are present ------------------------------
# Clones lvgl, libwally-core (+ its secp256k1 submodule), libqrencode and
# quirc.  Also provides ensure_emsdk() (invoked by scripts/build_web.sh) to
# install the pinned Emscripten SDK.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v git &>/dev/null; then
    echo "Missing: git" >&2
    exit 1
fi

clone_pinned() {
    local dir="$1"
    local repo="$2"
    local sha="$3"
    local tag="${4:-}"

    [ -n "$dir" ] || { echo "ERROR: empty dependency dir" >&2; exit 1; }

    # Fast path: already at the pinned commit (offline, no network).
    local current=""
    if [ -d "${PROJECT_ROOT}/${dir}/.git" ]; then
        current="$(git -C "${PROJECT_ROOT}/${dir}" rev-parse HEAD 2>/dev/null || true)"
    fi
    if [ "$current" = "$sha" ]; then
        return 0
    fi

    # Missing, empty, or at a different commit: (re)clone to the pinned SHA.
    if [ -n "$current" ]; then
        echo "Repairing ${dir}: at ${current}, expected ${sha} …"
    else
        echo "Cloning ${repo} @ ${sha}${tag:+ (${tag})} -> ${dir} …"
    fi
    rm -rf "${PROJECT_ROOT}/${dir}"
    git init "${PROJECT_ROOT}/${dir}"
    git -C "${PROJECT_ROOT}/${dir}" remote add origin "$repo"
    if [ -n "$tag" ]; then
        # Map the tag to a local ref (a bare `refs/tags/$tag` refspec only
        # records it in FETCH_HEAD), then verify the pinned SHA matches it.
        # Annotated tags peel to their commit via ^{}.
        git -C "${PROJECT_ROOT}/${dir}" fetch --depth 1 origin \
            "$sha" "refs/tags/$tag:refs/tags/$tag"
        local tagged
        tagged="$(git -C "${PROJECT_ROOT}/${dir}" rev-parse "refs/tags/$tag^{}" 2>/dev/null || true)"
        if [ "$tagged" != "$sha" ]; then
            echo "ERROR: ${dir}: tag ${tag} is ${tagged:-unresolved}, expected ${sha}" >&2
            exit 1
        fi
    else
        git -C "${PROJECT_ROOT}/${dir}" fetch --depth 1 origin "$sha"
    fi
    git -C "${PROJECT_ROOT}/${dir}" checkout --detach FETCH_HEAD

    local got
    got="$(git -C "${PROJECT_ROOT}/${dir}" rev-parse HEAD)"
    if [ "$got" != "$sha" ]; then
        echo "ERROR: ${dir} is at ${got}, expected ${sha}" >&2
        exit 1
    fi
}

# -- Emscripten SDK ---------------------------------------------------------
ensure_emsdk() {
    local emsdk_sha="5eb0bde7585670252e8ba05e9d361627bffd08b5" # tag 6.0.9
    local emsdk_ver="6.0.9"

    clone_pinned "external/emsdk" "https://github.com/emscripten-core/emsdk.git" \
        "$emsdk_sha" "$emsdk_ver"

    local emsdk_dir="${PROJECT_ROOT}/external/emsdk"
    local emcc_bin="${emsdk_dir}/upstream/emscripten/emcc"

    if [ ! -x "$emcc_bin" ]; then
        echo "Installing Emscripten ${emsdk_ver} (first run downloads ~500 MB)…"
        "${emsdk_dir}/emsdk" install "$emsdk_ver"
    fi

    # (Re)activate so emsdk_env.sh + ~/.emscripten stay in sync with this SDK.
    "${emsdk_dir}/emsdk" activate "$emsdk_ver"
}

clone_pinned "external/lvgl"          "https://github.com/lvgl/lvgl.git"                     "85aa60d18b3d5e5588d7b247abf90198f07c8a63" "v9.5.0"
clone_pinned "external/libwally-core" "https://github.com/ElementsProject/libwally-core.git" "0c41f38fb1c201786e9c3ac9eae4f5f80c051399" "release_1.5.6"
clone_pinned "external/libqrencode"   "https://github.com/fukuchi/libqrencode.git"           "715e29fd4cd71b6e452ae0f4e36d917b43122ce8" "v4.1.1"
clone_pinned "external/quirc"         "https://github.com/dlbeer/quirc.git"                  "542848dd6b9b0eaa9587bbf25b9bc67bd8a71fca" "v1.2"
clone_pinned "external/unity"         "https://github.com/ThrowTheSwitch/Unity.git"          "860062d51b2e8a75d150337b63ca2a472840d13c" "v2.6.0"

# libwally-core has its own submodule (secp256k1).  Its commit is pinned by
# libwally-core's gitlink, so `submodule update` checks out an exact SHA.
if [ -d "${PROJECT_ROOT}/external/libwally-core" ]; then
    git -C "${PROJECT_ROOT}/external/libwally-core" submodule update --init --recursive
fi
