load('ext://restart_process', 'docker_build_with_restart')
allow_k8s_contexts(os.environ['TILT_ALLOW_K8S_CONTEXT'])
default_registry(os.environ['TILT_REGISTRY'])

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

local_resource('make manifests', 'make controller-manifests', deps=["controller/api", "controller/internal", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go', 'controller/internal/pkg/webhookmanifests'])
local_resource('make generate', 'make controller-generate', deps=["controller/api", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go'])

local_resource(
    'CRD', 'make controller-manifests && kustomize build controller/config/crd | kubectl apply -f -', deps=["controller/api"],
    ignore=['controller/*/*/zz_generated.deepcopy.go'])

watch_file('./controller/config/')
k8s_yaml(kustomize('./controller/config/dev'))

local_resource(
    'WebhookCertJob Compile', 'make build-webhookcertjob-bin', deps=['controller/cmd/webhookcertjob/main.go'])

docker_build(
    'webhookcertjob:latest', './controller',
    dockerfile_contents=WEBHOOKCERTJOB_DOCKERFILE,
    entrypoint=['/webhookcertjob'],
    only=['./bin/webhookcertjob']
)

local_resource(
    'Controller Compile', 'make build-controller-bin', deps=['controller/internal', 'controller/api', 'controller/cmd/main.go'],
    ignore=['controller/*/*/zz_generated.deepcopy.go'])

docker_build_with_restart(
    'controller:latest', './controller',
    dockerfile_contents=MANAGER_DOCKERFILE,
    entrypoint=['/manager'],
    only=['./bin/manager'],
    live_update=[
        sync('./controller/bin/manager', '/manager'),
    ]
)

local_resource(
    'CNI Compile', 'make build-cni-bin', deps=['daemon/cmd/cni/main.go', 'daemon/pkg/cnipb'])

DAEMON_DOCKERFILE = '''FROM golang:alpine
RUN apk add --no-cache iptables ip6tables
WORKDIR /
COPY ./bin/daemon /
CMD ["/daemon"]
'''

local_resource(
    'Daemon Compile', 'make build-daemon-bin', deps=['daemon/cmd/juneaud/main.go', 'daemon/internal/daemon', 'daemon/pkg', 'daemon/bin/cni'],
    ignore=[])

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


BGP_SPEAKER_DOCKERFILE = '''FROM golang:alpine
RUN apk add --no-cache bird2
WORKDIR /
COPY ./bin/bgpspeaker /
CMD ["/bgpspeaker"]
'''

local_resource(
    'BGP Speaker Compile', 'make build-bgp-speaker-bin', deps=['bgp-speaker/cmd/bgpspeaker/main.go', 'bgp-speaker/internal'],
    ignore=[])

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
