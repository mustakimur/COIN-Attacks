TARGET_DIR="$PROJECT_ROOT""/scripts/SGX_SQLite/src/SGX_SQLite/"
SEMANTIC_LLVM="$PROJECT_ROOT""/src/semantics/llvm_src/build/"
SEMANTIC_EDL="$PROJECT_ROOT""/src/semantics/pyedl/"
CORE_DIR="$PROJECT_ROOT""/core/Triton/src/enclaveCoverage/coverage.py"

source /opt/intel/sgxsdk/environment

python "$SEMANTIC_EDL""/edlParse.py" "$TARGET_DIR""/Enclave/Enclave.edl"
"$SEMANTIC_LLVM""/bin/opt" -load "$SEMANTIC_LLVM""/lib/LLVMEnclaveSemantic.so" -EnclaveSemantic < "$TARGET_DIR""/enclave.so.0.4.opt.bc"

python $CORE_DIR "$TARGET_DIR""/enclave.so" unsafe_input_complete.tmp unsafe_ecall_stat.tmp > log
