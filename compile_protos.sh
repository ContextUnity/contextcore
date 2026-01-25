#!/bin/bash
set -e

PROTO_DIR="protos"
OUT_DIR="src/contextcore/generated"

mkdir -p $OUT_DIR
touch src/contextcore/__init__.py
touch src/contextcore/generated/__init__.py

# Compile protos with proper package structure
# Note: protoc generates absolute imports for cross-file imports by design
# When contextcore is installed as editable package (pip install -e .),
# Python will resolve these imports correctly through sys.path
uv run python -m grpc_tools.protoc \
    --proto_path=$PROTO_DIR \
    --python_out=$OUT_DIR \
    --grpc_python_out=$OUT_DIR \
    $PROTO_DIR/*.proto

# Fix imports: protoc generates "import context_unit_pb2" but we need relative imports
# for proper package structure. This is standard practice for protoc Python output.
find $OUT_DIR -name "*_pb2.py" -o -name "*_pb2_grpc.py" | while read file; do
    # Replace absolute imports with relative imports for context_unit_pb2
    sed -i 's/^import context_unit_pb2 as context__unit__pb2$/from . import context_unit_pb2 as context__unit__pb2/' "$file"
done

echo "Protos compiled successfully to $OUT_DIR"
echo "Note: Install contextcore as editable package: pip install -e ."
