#!/usr/bin/env bash
set -euo pipefail

OUTPUT_FLAG=""
while getopts "o:" opt; do
  case $opt in
    o)
      OUTPUT_FLAG="-o $OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

go build -trimpath -buildvcs=true -tags netgo -ldflags "-X main.version=0.1.0" $OUTPUT_FLAG ./cmd/wrapped
go test ./...
golangci-lint run ./...
