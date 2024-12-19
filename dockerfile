FROM ubuntu:22.04

RUN apt-get update && \
apt-get install -y build-essential cmake git libtool iproute2 python3 sudo nasm libssl-dev libgmp-dev && \
rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/intel/pailliercryptolib.git && \
git clone https://github.com/osu-crypto/libOTe.git && \
git clone https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping.git

WORKDIR /app/pailliercryptolib

RUN cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/path/to/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF && \
cmake --build build -j 10 && \
cmake --build build --target install -j 10 && \
export IPCL_DIR=/path/to/install/lib/cmake/ipcl-2.0.0/

WORKDIR /app/libOTe

RUN python3 build.py --all --boost --sodium && \
python3 build.py --install=./out/install/linux

WORKDIR /app/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping

RUN mkdir build

WORKDIR /app/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping/build

RUN cmake .. && \
make
