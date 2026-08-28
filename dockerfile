FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    vim \
    git \
    python3 \
    python3-pip \
    cmake \
    libgmp-dev \
    libspdlog-dev \
    libtool \
    nasm \
    libssl-dev \
    libmpfr-dev \
    iproute2 \
    net-tools \
    software-properties-common && \
    # install tcconfig for network interface configuration
    pip install tcconfig

# upgrade gcc g++ to version 13
RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get update && \
    apt-get install -y gcc-13 g++-13 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 90 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 90 && \
    update-alternatives --set gcc /usr/bin/gcc-13 && \
    update-alternatives --set g++ /usr/bin/g++-13


WORKDIR /app

RUN git clone https://github.com/intel/pailliercryptolib.git

WORKDIR /app/pailliercryptolib

RUN cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/app/out/install -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF && \
    cmake --build build -j && \
    cmake --build build --target install -j

WORKDIR /app
RUN git clone https://github.com/osu-crypto/libOTe.git 

WORKDIR /app/libOTe
RUN git checkout a403ec37c6a32148648b7d8fd66dc35318d9f99d && \
    python3 build.py --all --boost --sodium && \
    python3 build.py --install=/app/out/install

WORKDIR /app

COPY ./BLAKE3 ./BLAKE3
COPY ./FPSI-for-Hamming ./FPSI-for-Hamming
COPY ./frontend ./frontend
COPY ./fuzzy_mapping ./fuzzy_mapping
COPY ./Goldwasser-Micali ./Goldwasser-Micali
COPY ./RBOKVS ./RBOKVS
COPY ./CMakeLists.txt ./
COPY ./shell_run_bench.sh ./
COPY ./shell_run_bench_fmap.sh ./


RUN chmod +x ./*.sh && \
    mkdir build && \
    cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j 
