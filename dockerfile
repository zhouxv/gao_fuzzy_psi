FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y net-tools iproute2 python3 python3-pip
RUN pip install tcconfig
RUN apt-get install -y build-essential cmake git libtool sudo nasm libssl-dev libgmp-dev

WORKDIR /app

RUN git clone https://github.com/intel/pailliercryptolib.git && \
    git clone https://github.com/osu-crypto/libOTe.git

WORKDIR /app/libOTe

COPY ./boost_1_86_0.tar.bz2 ./out
RUN python3 build.py --all --boost --sodium && \
    python3 build.py --install=/app/out/install

WORKDIR /app/pailliercryptolib

RUN cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/app/out/install -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF && \
    cmake --build build -j && \
    cmake --build build --target install -j


WORKDIR /app

COPY ./BLAKE3 ./BLAKE3
COPY ./FPSI-for-Hamming ./FPSI-for-Hamming
COPY ./frontend ./frontend
COPY ./fuzzy_mapping ./fuzzy_mapping
COPY ./Goldwasser-Micali ./Goldwasser-Micali
COPY ./RBOKVS ./RBOKVS
COPY ./CMakeLists.txt ./
COPY ./run_bench.sh ./
COPY ./run_bench_hash.sh ./

# RUN chmod +x ./*.sh && \
#     mkdir build && \
#     cd build && \
#     cmake .. && \
#     make -j && \
#     cp ./main ../
