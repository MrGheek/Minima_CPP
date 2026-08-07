FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y \
    build-essential cmake \
    libsqlite3-dev libssl-dev zlib1g-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src/build
RUN cmake .. -DCMAKE_BUILD_TYPE=MinSizeRel && make -j$(nproc)

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libsqlite3-0 libssl3 zlib1g libcurl4 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/minima /usr/local/bin/minima
EXPOSE 9001 9002 9003 9004 9005
ENTRYPOINT ["minima"]
CMD ["-daemon"]
