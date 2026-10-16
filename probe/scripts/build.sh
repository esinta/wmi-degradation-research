#!/usr/bin/env bash
# Builds the probe and its real-WMI integration test binary into probe/dist/.
# Building is fine on the dev laptop; running either binary is not (it is
# soaking until 2026-10-19 ~20:00Z, and probe hosts must be isolated).
set -euo pipefail
cd "$(dirname "$0")/.."
commit="$(git rev-parse --short=12 HEAD)"
if [ -n "$(git status --porcelain -- .)" ]; then
	commit="${commit}-dirty"
fi
mkdir -p dist
gofmt -l . | (! grep .) || { echo "gofmt needed" >&2; exit 1; }
go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-X main.commit=${commit}" -o dist/probe2.exe ./cmd/probe2
GOOS=windows GOARCH=amd64 go test -c -tags wmiintegration -o dist/wmi-integration.test.exe ./internal/wmi
( cd dist && sha256sum probe2.exe wmi-integration.test.exe > SHA256SUMS )
echo "built dist/probe2.exe (${commit})"
cat dist/SHA256SUMS
