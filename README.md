# labsentry

<!-- BEGIN: REPO HERO -->
![labsentry — hero generated locally on the GPU stack](assets/repo-hero.png)
<!-- END: REPO HERO -->

Pure-C, zero-dependency sovereign AI-lab auditor + image pipeline.

Single static binary. Drop it on any node (x86_64 Linux, incl. Radxa edge
boards). No runtime, no package manager, no network required at runtime.

## What it does

- **scan** — walk one or more roots, classify assets (gguf, safetensors, lora,
  checkpoints, images, archives, native-build caches), SHA-256 hash, store a
  SQLite catalog, and emit a JSON report.
- **ports** — probe known AI-lab service ports and flag conflicts (e.g. Snap
  Prometheus squatting on :9090).
- **gpu** — count visible GPUs via /dev/nvidia*.
- **doctor** — run scan+ports+gpu and print a health verdict.
- **img** — image hygiene: rewrite every image to a random UUID filename and
  strip privacy metadata (PNG tEXt/zTXt/iTXt/tIME, JPEG APPn/COM, WebP EXIF/XMP).

## Invariant it enforces

Native build caches (`node-gyp`, `playwright`, `node_modules`, `.npm`, `ccache`,
`electron`, `*.o/*.so/*.a/*.node`) must NOT live on shared storage mounts
(`/mnt/...`). They belong on the root filesystem. The scanner flags violations.

## Build

    make            # static binary: ./labsentry
    make test       # compiles + runs smoke tests

Requires only gcc + make (tested gcc 15.2). SQLite3 amalgamation is vendored
under `vendor/` (public domain).

## Usage

    ./labsentry scan --roots /mnt/ai-storage:/home/scott/.ollama \
                     --db audit.db --json report.json --large-gb 10
    ./labsentry ports
    ./labsentry doctor --roots /mnt/ai-storage --db audit.db
    ./labsentry img --in ./incoming --out ./clean

## Query the catalog

    sqlite3 audit.db "SELECT type,count(*),sum(size)/1e9 gb \
                      FROM assets GROUP BY type;"
    sqlite3 audit.db "SELECT path FROM assets WHERE violation='duplicate';"
    sqlite3 audit.db "SELECT path FROM assets WHERE violation='native-build-cache-on-storage';"

## Monetization

Free OSS binary builds audience in self-host / LocalLLaMA circles. Paid layer:
productized "Lab Doctor" audit + hosted report + consultancy. Low maintenance,
inbound.

## Install

Prebuilt static binary (zero-dep, ~2.3 MB) — works on any x86_64 Linux:

    curl -fsSL https://raw.githubusercontent.com/Hardonian/labsentry/main/install.sh | sh

Or build from source (needs only gcc + make):

    git clone https://github.com/Hardonian/labsentry
    cd labsentry && make && sudo make install

## License

MIT (SQLite is public domain; sha256 is public domain).
