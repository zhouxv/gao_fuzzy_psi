# Fuzzy Private Set Intersection from Fuzzy Mapping

Please star this repository if it is helpful for your research.
That is important for me.

Please note that this implementation can only be used to test the efficiency of the FPSI protocols in [[GQL+24]](https://doi.org/10.1007/978-981-96-0938-3_2) ([full version](https://eprint.iacr.org/2024/1462)) for academic purposes.
The reason is that for the convenience of implementation, it fixes many parameters, such as secret keys, randomness and beaver triples that should be randomly generated in offline phase.

### Environment

This code and following instructions are tested on Ubuntu 22.04, with `g++ 11.4.0, CMake 3.22.1, GNU Make 4.3`.

## Build step by step

### Install dependencies

```bash
##############################
# install gmp
sudo apt install libgmp-dev

##############################
# install libOTe
git clone https://github.com/osu-crypto/libOTe.git
cd libOTe
python3 build.py --all --boost --sodium
python3 build.py --install=../out/install/
cd ..

##############################
# install pailliercryptolib
sudo apt-get install libtool
sudo apt-get install nasm
sudo apt-get install libssl-dev
git clone https://github.com/intel/pailliercryptolib.git
cd pailliercryptolib/
export IPCL_ROOT=$(pwd)
sudo cmake -S . -B build -DCMAKE_INSTALL_PREFIX=../out/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF
sudo cmake --build build -j
sudo cmake --build build --target install -j
cd ..

```

### Link pailliercryptolib

Since we use absolute path to link pailliercryptolib, it may be helpful to check line 42 of `Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping/CMakeLists.txt`:

```bash
set(IPCL_DIR "/path/to/install/lib/cmake/ipcl-2.0.0/")
```

In the path `IPCL_DIR`, there should exists the file `IPCLConfig.cmake`.

### Compile FPSI

```bash
##############################
# libOTe, pailliercryptolib, and Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping are three parallel folders in the same path
##############################
# download Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping
unzip Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping.zip
cd Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping

# in Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping
mkdir build && cd build
cmake ..
make
```

## Build with docker

We highly suggest using this dockerfile-based approach.

```bash
git clone https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping.git
cd Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping
docker build --no-cache -t [Your Image Name] .
docker run -itd --net=host --name [Your Container Name] --cap-add=NET_ADMIN [Your Image ID] /bin/bash
docker exec -it [Your Container ID] /bin/bash 
```

## Run the code

##### Print help information

```bash
./main
```

##### Run FPSI

Run our FPSI for L_1 distance in a 2-dimensional space with threshold of 8, Sender's set size of $2^5$, Receiver's set size of $2^6$, and intersection size of 17.

```bash
# run FPSI 
./main -fpsi -t11 -d 2 -delta 8 -s 5 -r 6 -i 17 -p 1
```

Run our FPSI for L_infty distance in a 3-dimensional space with threshold of 4, Sender's set size of $2^8$, Receiver's set size of $2^5$, and intersection size of 7.

```bash
# run FPSI 
./main -fpsi -t12 -d 3 -delta 4 -s 8 -r 5 -i 7
```

Run our FPSI for Hamming distance in a 128-dimensional space with threshold of 5, Sender's set size of $2^6$, Receiver's set size of $2^6$, and intersection size of 6.

```bash
# run FPSI 
./main -fpsi -t13 -hamdelta 5 -hams 6 -hamr 6 -hami 6
```
