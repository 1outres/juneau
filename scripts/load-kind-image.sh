#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
    printf 'usage: %s <cluster> <image>\n' "$0" >&2
    exit 2
fi

cluster=$1
image=$2
nodes=$(kind get nodes --name "$cluster")
if [[ -z $nodes ]]; then
    printf 'kind cluster %s has no nodes\n' "$cluster" >&2
    exit 1
fi

for node in $nodes; do
    docker save "$image" | docker exec -i "$node" ctr -n k8s.io images import -
done
