# --- Stage 1: build the WebAssembly kernel ---
FROM rust:1-slim AS wasm-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://rustwasm.github.io/wasm-pack/installer/init.sh | sh
RUN rustup target add wasm32-unknown-unknown

WORKDIR /build/wasm
COPY wasm/Cargo.toml wasm/Cargo.lock ./
COPY wasm/src ./src

RUN wasm-pack build --target web --release \
    && rm -f pkg/.gitignore pkg/package.json pkg/*.d.ts \
    && sed -i "s|new URL('meshcore_keygen_bg.wasm', import.meta.url)|new URL('meshcore_keygen_bg.wasm?v=2', import.meta.url)|" pkg/meshcore_keygen.js


# --- Stage 2: nginx serving the static site ---
FROM nginx:alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf

COPY index.html /usr/share/nginx/html/index.html
COPY README.md /usr/share/nginx/html/
COPY js /usr/share/nginx/html/js
COPY instructions /usr/share/nginx/html/instructions
COPY wasm/worker.js /usr/share/nginx/html/wasm/worker.js
COPY --from=wasm-builder /build/wasm/pkg /usr/share/nginx/html/wasm/pkg

EXPOSE 80
