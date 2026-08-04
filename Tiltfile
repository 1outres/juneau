load('ext://restart_process', 'docker_build_with_restart')

# mNi-Cloud/e2eを用いず、直接起動する場合は
# tilt config set default-context kind-mni-e2e

LABEL = 'juneau'

def _nix_env():
    j = decode_json(str(local('nix print-dev-env --json', quiet=True, echo_off=True)))
    nix_path = (j.get('variables', {}).get('PATH', {}) or {}).get('value', '')
    if not nix_path:
        return {}
    parent = os.getenv('PATH') or ''
    return {'PATH': nix_path + ':' + parent if parent else nix_path}

NIX_ENV = _nix_env()

WEBHOOKCERTJOB_DOCKERFILE = '''FROM golang:alpine
WORKDIR /
COPY ./bin/webhookcertjob /
CMD ["/webhookcertjob"]
'''

MANAGER_DOCKERFILE = '''FROM golang:alpine
WORKDIR /
COPY ./bin/manager /
CMD ["/manager"]
'''

local_resource('juneau-manifests', 'make controller-manifests', deps=["controller/api", "controller/internal", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go', 'controller/internal/pkg/webhookmanifests'], labels=[LABEL], env=NIX_ENV)
local_resource('juneau-generate', 'make controller-generate', deps=["controller/api", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go'], labels=[LABEL], env=NIX_ENV)

local_resource(
    'juneau-crd', 'make controller-manifests && kustomize build controller/config/crd | kubectl apply -f -', deps=["controller/api"],
    ignore=['controller/*/*/zz_generated.deepcopy.go'], labels=[LABEL], env=NIX_ENV)

watch_file('./controller/config/')
k8s_yaml(kustomize('./controller/config/dev'))

local_resource(
    'juneau-webhookcertjob-compile', 'make build-webhookcertjob-bin', deps=['controller/cmd/webhookcertjob/main.go'], labels=[LABEL], env=NIX_ENV)

docker_build(
    'webhookcertjob:latest', './controller',
    dockerfile_contents=WEBHOOKCERTJOB_DOCKERFILE,
    entrypoint=['/webhookcertjob'],
    only=['./bin/webhookcertjob']
)

local_resource(
    'juneau-controller-compile', 'make build-controller-bin', deps=['controller/internal', 'controller/api', 'controller/cmd/main.go'],
    ignore=['controller/*/*/zz_generated.deepcopy.go'], labels=[LABEL], env=NIX_ENV)

docker_build_with_restart(
    'controller:latest', './controller',
    dockerfile_contents=MANAGER_DOCKERFILE,
    entrypoint=['/manager'],
    only=['./bin/manager'],
    live_update=[
        sync('./controller/bin/manager', '/manager'),
    ]
)

DAEMON_DOCKERFILE = '''FROM golang:alpine
RUN apk add --no-cache iptables ip6tables
WORKDIR /
COPY ./bin/daemon /
CMD ["/daemon"]
'''

local_resource(
    'juneau-daemon-compile', 'make build-daemon-bin', deps=['daemon/cmd/juneaud/main.go', 'daemon/cmd/cni/main.go', 'daemon/internal/daemon', 'daemon/pkg', 'daemon/pkg/cnipb'],
    ignore=[], labels=[LABEL], env=NIX_ENV)

docker_build_with_restart(
    'daemon:latest', './daemon',
    dockerfile_contents=DAEMON_DOCKERFILE,
    entrypoint=['/daemon'],
    only=['./bin/daemon'],
    live_update=[
        sync('./daemon/bin/daemon', '/daemon'),
    ]
)

watch_file('./daemon/config/')
k8s_yaml(kustomize('./daemon/config/default'))


BGP_SPEAKER_DOCKERFILE = '''FROM alpine:3.23
RUN apk add --no-cache bird
WORKDIR /
COPY ./bin/bgpspeaker /
CMD ["/bgpspeaker"]
'''

local_resource(
    'juneau-bgp-speaker-compile', 'make build-bgp-speaker-bin', deps=['bgp-speaker/cmd/bgpspeaker/main.go', 'bgp-speaker/internal'],
    ignore=[], labels=[LABEL], env=NIX_ENV)

docker_build_with_restart(
    'bgp-speaker:latest', './bgp-speaker',
    dockerfile_contents=BGP_SPEAKER_DOCKERFILE,
    entrypoint=['/bgpspeaker'],
    only=['./bin/bgpspeaker'],
    live_update=[
        sync('./bgp-speaker/bin/bgpspeaker', '/bgpspeaker'),
    ]
)

watch_file('./bgp-speaker/config/')
k8s_yaml(kustomize('./bgp-speaker/config/default'))
