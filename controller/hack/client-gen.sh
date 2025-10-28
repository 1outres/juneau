#!/usr/bin/env bash

source "$HOME"/go/pkg/mod/k8s.io/code-generator@v0.32.1/kube_codegen.sh

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

echo $SCRIPT_ROOT

kube::codegen::gen_client \
  --output-dir "$SCRIPT_ROOT"/pkg/client \
  --output-pkg github.com/1outres/juneau/controller/pkg/client \
  --boilerplate "$SCRIPT_ROOT"/hack/boilerplate.go.txt \
  "$SCRIPT_ROOT"
