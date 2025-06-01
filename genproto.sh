#!/usr/bin/env bash
set -e
PROJECT_ROOT=$(git rev-parse --show-toplevel)
PROTOS_DIR="$PROJECT_ROOT/protos"
GEN_GO_DIR="$PROJECT_ROOT/gen/go"
echo "Cleaning up old generated Go files from $GEN_GO_DIR ..."
rm -rf "$GEN_GO_DIR"/*
mkdir -p "$GEN_GO_DIR"
echo "Generating Go gRPC stubs..."
find "$PROTOS_DIR" -path '*/archive/*' -prune -o -name '*.proto' -print0 | while IFS= read -r -d $'\0' proto_file; do
  relative_proto_path=$(echo "$proto_file" | sed "s|^$PROTOS_DIR/||")
  echo "  Processing: $relative_proto_path from $PROTOS_DIR"
  protoc \
    -I="$PROTOS_DIR" \
    --go_out="$GEN_GO_DIR" --go_opt=paths=source_relative \
    --go-grpc_out="$GEN_GO_DIR" --go-grpc_opt=paths=source_relative \
    "$proto_file"
done
echo "✅ Go gRPC stubs generated successfully in '$GEN_GO_DIR'"
