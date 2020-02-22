#! /bin/bash

NUM=$1
SLEEPTIME=$2
for i in `seq 1 $NUM`
do
  python3 user-test-rp-throughput.py 127.0.0.1 127.0.0.1 1 &
  sleep $SLEEPTIME
done
