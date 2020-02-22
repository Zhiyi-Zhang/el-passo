#! /bin/bash

NUM=$1
for i in `seq 1 $NUM`
do
  python3 user-test-idp-throughput.py 127.0.0.1 127.0.0.1 1 &
done
