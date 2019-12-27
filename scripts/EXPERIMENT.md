# Experiment

## Background
To experiment of COIN Attacks framework, we deliver 8 micro-benchmark for 8 security sensitive policy. The micro-benchmarks are each a seperate SGX project. The experiment also includes SGX_SQLite project cloned from https://github.com/yerzhan7/SGX_SQLite (because original repository has pending pull request from us for the patches that could be merged in the meantime). Note, we are working on to include the other experimented projects.

## Usage
To experiment the micro-benchmark, follow the instructions:
```
export PROJECT_ROOT=path_to_repository_head
# if you are using the docker image, it would be
# export PROJECT_ROOT=/home/COIN-Attacks/

cd $PROJECT_ROOT/scripts/PoCs/
./run.sh

# Following will be on your screen
Select your benchmark:
1)use-after-free
2)double-free
3)stack overflow
4)heap overflow
5)stack memory leak
6)heap memory leak
7)null pointer dereference
8)ineffectual condition

# use the number to test one of the benchmark
1

# The will trigger the benchmark compilation and run the analysis.
# The report will be available in the current direct as coin_report<benchmark_id>
```

## Description
We are going to describe the reports for each of the micro-benchmark.

### Use-after-free
