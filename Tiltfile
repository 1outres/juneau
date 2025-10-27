
# ========== Controller ===========

load('ext://restart_process', 'docker_build_with_restart')
allow_k8s_contexts(os.environ['TILT_ALLOW_K8S_CONTEXT'])
default_registry(os.environ['TILT_REGISTRY'])

DOCKERFILE = '''FROM golang:alpine
WORKDIR /
COPY ./bin/manager /
CMD ["/manager"]
'''

# Generate manifests and go files
local_resource('make manifests', 'make manifests', deps=["controller/api", "controller/internal", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller/')
local_resource('make generate', 'make generate', deps=["controller/api", "controller/hooks"], ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller')

# Deploy CRD
local_resource(
    'CRD', 'make manifests; kustomize build config/crd | kubectl apply -f -', deps=["controller/api"],
    ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller/')

# Deploy manager
watch_file('./controller/config/')
k8s_yaml(kustomize('./controller/config/dev'))

local_resource(
    'Watch & Compile', 'make generate; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/manager cmd/main.go', deps=['controller/internal', 'controller/api', 'controller/cmd/main.go'],
    ignore=['controller/*/*/zz_generated.deepcopy.go'], dir='controller/')

docker_build_with_restart(
    'controller:latest', './controller',
    dockerfile_contents=DOCKERFILE,
    entrypoint=['/manager'],
    only=['./bin/manager'],
    live_update=[
        sync('./controller/bin/manager', '/manager'),
    ]
)

# ========== Daemon ===========

local_resource('protobuf', 'protoc --go_out=. --go-grpc_out=. proto/juneau.v1.proto', deps=['daemon/proto/juneau.v1.proto'], dir='daemon/')
