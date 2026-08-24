# open62541 built with discovery and the multicast extension, so the server can
# act as a Local Discovery Server and answer FindServersOnNetwork.
FROM debian:bookworm-slim AS build

ARG OPEN62541_VERSION=v1.4.6

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The multicast extension lives in the deps/mdnsd submodule, so a plain
# shallow clone is not enough.
RUN git clone --depth 1 --recurse-submodules --shallow-submodules \
        --branch ${OPEN62541_VERSION} \
        https://github.com/open62541/open62541.git

WORKDIR /src/open62541/build
RUN cmake -DUA_ENABLE_AMALGAMATION=ON \
          -DUA_ENABLE_DISCOVERY=ON \
          -DUA_ENABLE_DISCOVERY_MULTICAST=ON \
          -DCMAKE_BUILD_TYPE=Release .. \
    && make -j"$(nproc)"

WORKDIR /app
COPY server_lds.c .
RUN cp /src/open62541/build/open62541.c /src/open62541/build/open62541.h . \
    && gcc -std=c99 -O2 -I. server_lds.c open62541.c -o server -lpthread

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libc6 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/server .
CMD ["./server"]
