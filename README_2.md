## run docker

```bash
sudo docker build -t gao_artifact .
sudo docker run -dit --name gao_artifact --cap-add=NET_ADMIN gao_artifact:latest
```

```
tcset lo --rate 100Mbps --delay 80ms --overwrite
```

```
nohup ./shell_run_bench_fmap.sh > log 2>&1 &
```
