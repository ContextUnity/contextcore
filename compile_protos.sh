#!/bin/bash
set -e

PROTO_DIR="protos"
OUT_DIR="src/contextunity/core"

# Compile all protos directly into the cu.core package root.
# No separate generated/ directory — all stubs live alongside the code.
uv run python -m grpc_tools.protoc \
    -Iprotos \
    --python_out=src/contextunity/core \
    --pyi_out=src/contextunity/core \
    --grpc_python_out=src/contextunity/core \
    protos/*.proto

# Fix imports: protoc generates "import contextunit_pb2" but we need
# relative imports for proper package structure.
find $OUT_DIR -maxdepth 1 -name "*_pb2.py" -o -name "*_pb2_grpc.py" -o -name "*.pyi" | while read file; do
    sed -i 's/^import contextunit_pb2 as contextunit__pb2$/from . import contextunit_pb2 as contextunit__pb2/' "$file"
    sed -i 's/^import contextunit_pb2 as _contextunit_pb2$/from . import contextunit_pb2 as _contextunit_pb2/' "$file"
done

echo "Protos compiled to $OUT_DIR"
echo "Stubs: brain, commerce, contextunit, router, worker, shield, zero, admin"

echo "Formatting generated python files to comply with linters..."
uv run ruff check --fix "$OUT_DIR"/*_pb2*.py*
uv run ruff format "$OUT_DIR"/*_pb2*.py*
echo "Formatting complete!"
