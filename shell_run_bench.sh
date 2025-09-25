#! /bin/bash
set -e

# Cleanup function to handle script termination
# This function will be called on script exit or interruption
cleanup() {
    pkill -P $$  # Kill all the child processes of the current process group
    # Optional: Delete temporary files
    [ -f "$TMP_FILE" ] && rm "$TMP_FILE"
    exit 1
}

# Register Signal Capture
trap 'cleanup' INT TERM EXIT

ns=(8)
ms=(0 1 2)
dims=(2 5 8)
deltas=(16 64 256)

printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

# 循环执行
for n in "${ns[@]}"; do
  for dim in "${dims[@]}"; do
    for m in "${ms[@]}"; do
      for delta in "${deltas[@]}"; do
        ./build/main -n $n --dim $dim -m $m --delta $delta --times 3
      done
      echo   # 输出空行
    done
  done
done



