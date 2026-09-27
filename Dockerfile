# Stage 1: Install Python dependencies (cached unless requirements.txt changes)
#
# 3.14 is what this project is developed on, and the ceiling that `requires-python =
# ">=3.11"` leaves open; the CI matrix runs the suite on 3.11, 3.12 and 3.14, so the range
# is tested rather than assumed. It is not here for speed — an analysis spends its wall
# clock in the detection binaries, the subprocesses around them and the database, and the
# interpreter only shows up in the pure-Python passes (analytics, lineage, markers).
FROM python:3.14-slim AS deps

WORKDIR /app

COPY requirements.txt .

# CXX/LDCXXSHARED are load-bearing, and what they prevent fails SILENTLY.
#
# `python:3.14-slim` records `CXX = gcc` and `LDCXXSHARED = gcc -shared` in its sysconfig
# where 3.12-slim recorded `g++` — that CPython was configured in an environment without
# g++, and every C++ extension built from an sdist inherits the answer. `py-tlsh` is the
# one C++ sdist in requirements.txt (it publishes no wheels, so every image compiles it),
# and linked by `gcc` it comes out with no libstdc++: `import tlsh` then raises
# `ImportError: undefined symbol: __gxx_personality_v0`. Both call sites in
# app/similarity/hasher.py catch ImportError deliberately, so the image would boot, report
# healthy, log one warning in a worker nobody reads, and silently stop computing similarity
# hashes — with the whole suite still green, because the host builds it correctly.
#
# The import check is the guard; the env vars are only the current fix for it. It fails the
# BUILD, here, rather than leaving a feature switched off in production.
RUN apt-get update && apt-get install -y --no-install-recommends \
    file \
    curl \
    gosu \
    build-essential \
    && CXX=g++ LDCXXSHARED="g++ -shared" pip install --no-cache-dir -r requirements.txt \
    && python -c "import tlsh; assert tlsh.hash(bytes(range(256)) * 8)" \
    && apt-get purge -y build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Production CSS.
#
# Without this the image would ship `base.html` in **dev mode** — a `<script>` tag loading
# the Tailwind Play CDN bundle, which is a JIT compiler that recompiles every utility class
# in the browser on every page load, and which needs `style-src 'unsafe-inline'` to inject
# what it produces — while `scripts/package.sh` ships production CSS in the *archive*.
#
# Its own stage so the ~46 MB CLI download is cached independently of the app layer and
# never reaches the runtime image — only the two files it produces are copied forward.
FROM deps AS css

WORKDIR /app

# Keep in step with TAILWIND_VERSION in Taskfile.yml.
ARG TAILWIND_VERSION=3.4.17

COPY app/static/tailwind-input.css app/static/tailwind-input.css
COPY app/static/vendor app/static/vendor
COPY app/templates app/templates

# A release archive already CONTAINS the compiled stylesheet — `task package` runs
# `css:build` before it packs — so rebuilding it here would download a 46 MB CLI from GitHub
# to reproduce a file already in the tree, and make `task deploy ARCHIVE=…` need the
# internet on every host, which is the one thing an air-gapped install cannot have.
#
# The discriminator is base.html's OWN MODE, not merely the file existing:
# `tailwind-built.css` is TRACKED, so every checkout has one and it is routinely stale —
# Tailwind scans the templates to decide which classes to emit, so a class added to a
# template today is absent from a stylesheet compiled last week. `task package` flips
# base.html to the compiled sheet and writes it in the same step, so "base.html already
# points at the compiled sheet" means exactly "this tree was packaged" and nothing else. A
# working tree carries the Play-CDN block and still gets a fresh build.
#
# The swap and both assertions run either way, so a half-swapped base.html still fails here
# rather than in a browser.
RUN set -eu; \
    if [ -s app/static/vendor/tailwind-built.css ] \
       && grep -q 'vendor/tailwind-built.css' app/templates/base.html; then \
      echo "tailwind: using the stylesheet shipped in this tree ($(wc -c < app/static/vendor/tailwind-built.css) bytes)"; \
      cp app/static/vendor/tailwind-built.css /tmp/tailwind-built.css; \
    else \
      echo "tailwind: not a packaged tree — compiling the stylesheet"; \
      arch="$(uname -m)"; \
      case "$arch" in \
        x86_64) tw_arch=x64 ;; \
        aarch64|arm64) tw_arch=arm64 ;; \
        *) echo "unsupported architecture for the Tailwind CLI: $arch" >&2; exit 1 ;; \
      esac; \
      curl -fsSL -o /usr/local/bin/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-${tw_arch}"; \
      chmod +x /usr/local/bin/tailwindcss; \
      tailwindcss -i app/static/tailwind-input.css -o /tmp/tailwind-built.css \
        --content "app/templates/**/*.html" --minify; \
    fi; \
    # The same swap `task css:build` performs, inlined rather than shelling out to `task`
    # (go-task is not in this image, and adding it for one substitution is not worth it).
    # Emitting the END marker literally keeps it idempotent (see the css:build note in
    # taskfiles/dev.yml).
    perl -i -0777 -pe \
      's{(<!-- TAILWIND:START -->\n).*?<!-- TAILWIND:END -->}{$1  <link rel="stylesheet" href="/static/vendor/tailwind-built.css">\n  <!-- TAILWIND:END -->}s' \
      app/templates/base.html; \
    grep -q 'tailwind-built.css' app/templates/base.html \
      || { echo "base.html was not switched to the compiled stylesheet" >&2; exit 1; }; \
    grep -q 'vendor/tailwind.js' app/templates/base.html \
      && { echo "base.html still loads the Play CDN bundle" >&2; exit 1; }; \
    true

# Stage 3: Application image
FROM deps AS app

WORKDIR /app

COPY . .

# Production CSS over the dev-mode files `COPY . .` just laid down.
COPY --from=css /tmp/tailwind-built.css app/static/vendor/tailwind-built.css
COPY --from=css /app/app/templates/base.html app/templates/base.html

RUN addgroup --system --gid 999 appgroup \
    && adduser --system --uid 999 --ingroup appgroup --no-create-home appuser \
    && mkdir -p uploads /data \
    && chown -R appuser:appgroup uploads /data

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
