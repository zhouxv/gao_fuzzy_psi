#!/bin/bash

# 参数数组
ns=(5 8)
ms=(18 20)
rs=(10 30)
ds=(2 6)

# 循环执行
for n in "${ns[@]}"; do
  for m in "${ms[@]}"; do
    for r in "${rs[@]}"; do
        for d in "${ds[@]}"; do
        ./main -shash -d $d -delta $r -s $n -r $m -i 7
        echo   # 输出空行
      done
    done
  done
done