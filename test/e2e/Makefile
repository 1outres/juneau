.PHONY: test up down

# Run the full E2E suite (default: 2 workers, no BGP router unless tests start it).
# Uses the Ginkgo CLI so we can spawn worker processes; --procs=4 spreads
# parallelizable specs (connectivity matrix, probe, host-network, allocation,
# subnet-routetable, service-vpc) across 4 procs while the bgp/nat blocks
# are Serial-tagged and stay on Node 1.
test:
	go run github.com/onsi/ginkgo/v2/ginkgo --procs=4 -v --timeout=60m ./...

# Bring up just the kind cluster + controllers/daemons (no behavioral specs).
# Knobs (env vars):
#   E2E_WORKER_NODES=<n>   number of kind worker nodes (default 2)
#   E2E_BGP_ROUTER=true    also start the bird-based BGP peer container
#   E2E_SKIP_BUILD=true    skip image rebuilds when the tag already exists
#   E2E_KEEP_CLUSTER=true  forced on by this target
up:
	E2E_KEEP_CLUSTER=true go test -run TestE2E -v -ginkgo.v \
	  -ginkgo.label-filter=bringup -timeout 30m ./...

# Tear down the kind cluster and BGP peer container (if any).
down:
	kind delete cluster --name juneau-e2e || true
	docker rm -f juneau-e2e-bgp-peer 2>/dev/null || true
