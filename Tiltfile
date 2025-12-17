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

local_resource('make manifests', 'make manifests', deps=["controller/api", "controller/internal", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go', 'controller/internal/pkg/webhookmanifests'], dir='controller/')
local_resource('make generate', 'make generate', deps=["controller/api", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller')

local_resource(
    'CRD', 'make manifests; kustomize build config/crd | kubectl apply -f -', deps=["controller/api"],
    ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller/')

watch_file('./controller/config/')
k8s_yaml(kustomize('./controller/config/dev'))

local_resource(
    'WebhookCertJob Compile', 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/webhookcertjob cmd/webhookcertjob/main.go', deps=['controller/cmd/webhookcertjob/main.go'], dir='controller/')

docker_build(
    'webhookcertjob:latest', './controller',
    dockerfile_contents=WEBHOOKCERTJOB_DOCKERFILE,
    entrypoint=['/webhookcertjob'],
    only=['./bin/webhookcertjob']
)

local_resource(
    'Controller Compile', 'make generate; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/manager cmd/main.go', deps=['controller/internal', 'controller/api', 'controller/cmd/main.go'],
    ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller/')

docker_build_with_restart(
    'controller:latest', './controller',
    dockerfile_contents=MANAGER_DOCKERFILE,
    entrypoint=['/manager'],
    only=['./bin/manager'],
    live_update=[
        sync('./controller/bin/manager', '/manager'),
    ]
)

local_resource('protobuf', 'protoc --go_out=module=github.com/1outres/juneau/daemon:. --go-grpc_out=module=github.com/1outres/juneau/daemon:. pkg/cnipb/cni.proto', deps=['daemon/pkg/cnipb/cni.proto'], dir='daemon/')

local_resource(
    'CNI Compile', 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/cni cmd/cni/main.go', deps=['daemon/cmd/cni/main.go', 'daemon/pkg/cnipb'], dir='daemon/')

DAEMON_DOCKERFILE = '''FROM golang:alpine
WORKDIR /
COPY ./bin/daemon /
CMD ["/daemon"]
'''

local_resource(
    'Daemon Compile', 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/daemon cmd/juneaud/main.go', deps=['daemon/cmd/juneaud/main.go', 'daemon/internal/daemon', 'daemon/pkg', 'daemon/bin/cni'],
    ignore=[], dir='daemon/')

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
