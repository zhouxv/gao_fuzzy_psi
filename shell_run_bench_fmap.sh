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

ns=(8 12)
dims=(2 6 10 15)
deltas=(10 60 250)

printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

# 循环执行
for n in "${ns[@]}"; do
  for dim in "${dims[@]}"; do
    for delta in "${deltas[@]}"; do
      ./build/main -fmap -d $dim -delta $delta -s $n -r $n -i 7 -trait 3
      # ./build/main -fpsi -t11 -d $dim -delta $delta -s $n -r $n -i 7 -p 1 -trait 3
      # ./build/main -fpsi -t11 -d $dim -delta $delta -s $n -r $n -i 7 -p 2 -trait 3
      echo   # 输出空行
    done
  done
done



