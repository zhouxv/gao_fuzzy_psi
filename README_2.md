```bash
sudo docker build -t gao_ufpsi:latest .

sudo docker run -dit --name gao_ufpsi_100Mbps --cap-add=NET_ADMIN --cpuset-cpus="64,66,68,70,72,74,76,78,80,82,84,86,88,90,92,94" --cpus=16 --memory=128g --memory-swap=128g gao_ufpsi:latest

sudo docker run -dit --name gao_ufpsi_10Mbps --cap-add=NET_ADMIN --cpuset-cpus="96,98,100,102,104,106,108,110,112,114,116,118,120,122,124,126" --cpus=16 --memory=128g --memory-swap=128g gao_ufpsi:latest
```

In our image, we use [tcconfig](!https://github.com/thombashi/tcconfig) to set up traffic control of network bandwidth/latency. Usage instructions are provided below.

```bash
tcset lo --rate 10Gbps --overwrite               # Set the local loopback interface bandwidth to 10Gbps
tcset lo --rate 1Gbps --delay 5ms --overwrite    # Set bandwidth to 1Gbps and add 5ms network delay
tcset lo --rate 100Mbps --delay 80ms --overwrite # Set bandwidth to 100Mbps and add 20ms network delay
tcset lo --rate 10Mbps --delay 80ms --overwrite # Set bandwidth to 100Mbps and add 20ms network delay
tcshow lo                                        # Display current traffic control settings for the loopback interface
tcdel lo -a                                      # Remove all traffic control rules from the loopback interface
```
