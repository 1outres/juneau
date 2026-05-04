# kubectl-juneau

`kubectl juneau` is a kubectl plugin for inspecting Juneau networking
state from outside the cluster. The current build covers the
**Tier 1** commands — read-only walks of the Juneau resource graph
with no per-Node BPF inspection. Tier 2 (data-plane reads) and Tier 3
(reachability + probe) will follow as separate releases.

## Install

Build from source:

```sh
make -C kubectl-juneau build
# binary lands at kubectl-juneau/bin/kubectl-juneau
mv kubectl-juneau/bin/kubectl-juneau /usr/local/bin/
```

`kubectl` discovers any executable named `kubectl-<name>` on `$PATH`,
so once the binary is on `$PATH` it is invokable as
`kubectl juneau ...`.

## Tier 1 commands

### `kubectl juneau version`

Print build identity. `-o json` / `-o yaml` are supported.

### `kubectl juneau describe pod NAME`

Walks Pod → NetworkInterface → Subnet → Vpc → RouteTable → NetworkACL
→ SecurityGroups → ElasticIP and renders the chain as a tree.

```text
Pod  default/nginx  (Node: worker-1, podIP: 10.80.0.5)
`-- NetworkInterface  nginx.eth0  (phase: Ready, address: 10.80.0.5)
    |-- Subnet  app-subnet  (cidr: 10.80.0.0/24, vni: 2)
    |   |-- Vpc  app-vpc  (vpcID: 2, enableService: true, enforceSecurityGroups: false)
    |   |-- RouteTable  app-vpc  (main, 3 routes)
    |   |   |-- 10.80.0.0/24  ->  connected (app-subnet)
    |   |   |-- 10.80.1.0/24  ->  connected (client-subnet)
    |   |   `-- 0.0.0.0/0     ->  natGateway (egress-natgw)
    |   `-- NetworkACL  web-acl  (aclID: 1, ingress: 1, egress: 0, rulesetVersion: 1)
    |-- SecurityGroups  (1)
    |   `-- web-sg  (groupID: 2, ingress: 1, egress: default-allow)
    `-- ElasticIP  (none)
```

### `kubectl juneau describe vpc NAME`

Lists every Subnet, RouteTable, SecurityGroup, NetworkACL and
NATGateway that lives inside the named Vpc.

### `kubectl juneau describe subnet NAME`

Subnet-centric view: owning Vpc, resolved RouteTable (main vs override),
attached NetworkACL, gateway / DNS VIPs, and NetworkInterfaces hosted
in this Subnet.

### `kubectl juneau describe service NAME`

Surfaces the Service's Vpc binding (annotation), shared flag, ports,
and per-backend rows. Each backend row marks `[VPC mismatch]` when
the backend Pod's owning Vpc is not the Service's owning Vpc.

### `kubectl juneau describe networkinterface NAME`

Single NetworkInterface focus: Pod / Node / Subnet / Vpc / RouteTable
/ NetworkACL / SecurityGroups / ElasticIP, similar to `describe pod`
but rooted at the NetworkInterface object directly. Aliases: `nic`,
`ni`, `iface`.

## Output formats

All commands accept `-o tree` (default), `-o json`, `-o yaml`. The
domain types under `internal/topology` are JSON/YAML-tagged so
structured output is stable across releases.

## Architecture

```
cmd/kubectl-juneau/
  main.go                    process boundary (argv, IOStreams, exit)

internal/
  cmd/                       cobra layer — no business logic
    root.go                  ConfigFlags + child registration
    version/                 version subcommand
    describe/                describe parent + per-kind files
                             (pod / vpc / subnet / service / networkinterface)
  factory/                   single I/O seam (kube client, future NodeAgent)
    nodeagent/               Tier-2 reservation point
  topology/                  CRD-graph walk (pure logic over View)
    view.go                  View interface (the I/O abstraction)
    kubeview.go              production View backed by controller-runtime
    routing.go               RouteTable + ACL + SG summary helpers
    pod_context.go           Resolve* entry points
    vpc_context.go
    subnet_context.go
    service_context.go
  output/                    rendering (tree / json / yaml)
  version/                   build-time identity
```

The cmd layer's only responsibilities are flag parsing and renderer
selection. Business logic lives in `topology/`, which exposes one
`Resolve<X>Context` per command and returns presenter-friendly DTOs.
This split keeps tests trivial: fake the `topology.View` interface and
the resolvers are exercised without any cluster.

### Future tiers

`internal/factory/nodeagent` reserves the surface that Tier 2 will use
to talk to per-Node `juneaud` debug endpoints. The kube-backed Factory
returns `ErrNotImplemented` today; a future build will wire a real
client. Adding a Tier 2 column to `describe pod` (e.g. `--with-bpf`)
is then a local change to `cmd/describe/pod.go` plus the new client —
no churn in `topology/`.
