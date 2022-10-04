#!/bin/bash

killall -9 trackmania-fuzzer
export CROSS_CC="gcc -m32"

cargo run -- --noformat
