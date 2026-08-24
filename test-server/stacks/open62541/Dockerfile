# Builds open62541 from source as a single amalgamated file, then compiles the
# test server against it. Pinned to a release so the matrix does not change
# underneath the tests.
FROM debian:bookworm-slim AS build

ARG OPEN62541_VERSION=v1.4.6

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch ${OPEN62541_VERSION} \
        https://github.com/open62541/open62541.git

WORKDIR /src/open62541/build
RUN cmake -DUA_ENABLE_AMALGAMATION=ON -DCMAKE_BUILD_TYPE=Release .. \
    && make -j"$(nproc)"

WORKDIR /app
COPY server.c .
RUN cp /src/open62541/build/open62541.c /src/open62541/build/open62541.h . \
    && gcc -std=c99 -O2 -I. server.c open62541.c -o server -lpthread

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libc6 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/server .
EXPOSE 48020
CMD ["./server"]
