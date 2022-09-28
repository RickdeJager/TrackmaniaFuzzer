# Trackmania nations forever fuzzer

This repository is accompanied by two blog posts:
1. [Hacking TMNF: Part 1 - Fuzzing the game server](https://blog.bricked.tech/posts/tmnf/part1/)
2. [Hacking TMNF: Part 2 - Exploiting a blind format string ](https://blog.bricked.tech/posts/tmnf/part2/)

# Fuzzer
## Setup
1. Download and extract the trackmania server in the "Server" directory in the repository.
1. Ensure that the user that will be running the fuzzer does not have permission to create new files here. You _will_ have a bad time if you don't do this, as RPC calls can legitimately create new files.

## Running
1. execute the "run.sh" script from within "./GrammarFuzzer"
1. wait for the server to initialize and run `python3 kick.py` to send the initial RPC message

## Triaging
1. execute the "repro.sh" script from within "./GrammarFuzzer" to get the raw XML files that caused a crash.