#!/bin/bash
set -e

PROTO_DIR="protos"
OUT_DIR="src/contextcore"

# Compile all protos directly into the contextcore package root.
# No separate generated/ directory — all stubs live alongside the code.
uv run python -m grpc_tools.protoc \
    --proto_path=$PROTO_DIR \
    --python_out=$OUT_DIR \
    --grpc_python_out=$OUT_DIR \
    $PROTO_DIR/*.proto

# Fix imports: protoc generates "import context_unit_pb2" but we need
# relative imports for proper package structure.
find $OUT_DIR -maxdepth 1 -name "*_pb2.py" -o -name "*_pb2_grpc.py" | while read file; do
    sed -i 's/^import context_unit_pb2 as context__unit__pb2$/from . import context_unit_pb2 as context__unit__pb2/' "$file"
done

echo "Protos compiled to $OUT_DIR"
echo "Stubs: brain, commerce, context_unit, router, worker, shield, zero, admin"
