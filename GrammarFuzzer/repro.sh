#!/bin/bash
export CROSS_CC="gcc -m32"

cargo run -- --repro
