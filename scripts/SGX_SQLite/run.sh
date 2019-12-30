export PROJECT_ROOT="$PWD""/../../"
export LLVM_BUILD="$PROJECT_ROOT/src/semantics/llvm_src/build"
export SEMANTICS_DIR="$PROJECT_ROOT/src/semantics/pyedl"
export SYMEMU="$PROJECT_ROOT/src/core/Triton/src/enclaveCoverage"

source /opt/intel/sgxsdk/environment

PROJECT_DIR="$PROJECT_ROOT/scripts/SGX_SQLite"

cd $PROJECT_DIR
make clean
make SGX_MODE=SIM
cd "$OLDPWD"

python "$SEMANTICS_DIR/edlParse.py" "$PROJECT_DIR/Enclave/Enclave.edl"
"$LLVM_BUILD/bin/opt" -load "$LLVM_BUILD/lib/LLVMEnclaveSemantic.so" -EnclaveSemantic  < "$PROJECT_DIR/enclave.so.0.4.opt.bc"

python "$SYMEMU/coverage.py" "$PROJECT_DIR/enclave.so" unsafe_input_complete.tmp unsafe_ecall_stat.tmp > "coin_report$choice"
