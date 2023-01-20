#!/bin/bash

killall -9 trackmania-fuzzer
chmod -R -w ../Server/GameData
export CROSS_CC="gcc -m32"

cargo run -- --noformat
