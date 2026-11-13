# DecryptLab Ultimate — single-image build (API + installable PWA).
# Serves the web app AND the C++ core API from one binary on $PORT.

# ---- build stage ----
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake libssl-dev zlib1g-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)"

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3 zlib1g libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 dlu
WORKDIR /app
COPY --from=build /src/build/bin/decryptlab-api /app/decryptlab-api
COPY --from=build /src/build/bin/decryptlab      /app/decryptlab
COPY --from=build /src/apps/web                   /app/web
USER dlu
ENV PORT=8090
EXPOSE 8090
# $PORT is honoured automatically (Render/Railway/Fly/Koyeb inject it).
CMD ["/app/decryptlab-api", "--web", "/app/web"]
