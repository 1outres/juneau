load('ext://restart_process', 'docker_build_with_restart')
allow_k8s_contexts(os.environ['TILT_ALLOW_K8S_CONTEXT'])
default_registry(os.environ['TILT_REGISTRY'])

DOCKERFILE = '''FROM golang:alpine
WORKDIR /
COPY ./bin/manager /
CMD ["/manager"]
'''

# Generate manifests and go files
local_resource('make manifests', 'make manifests', deps=["api", "internal", "hooks"], ignore=['*/*/zz_generated.deepcopy.go'], dir='controller/')
local_resource('make generate', 'make generate', deps=["api", "hooks"], ignore=['*/*/zz_generated.deepcopy.go'], dir='controller')

# Deploy CRD
local_resource(
    'CRD', 'make manifests; kustomize build config/crd | kubectl apply -f -', deps=["api"],
    ignore=['*/*/zz_generated.deepcopy.go'], dir='controller/')

# Deploy manager
watch_file('./controller/config/')
k8s_yaml(kustomize('./controller/config/dev'))

local_resource(
    'Watch & Compile', 'make generate; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/manager cmd/main.go', deps=['internal', 'api', 'cmd/main.go'],
    ignore=['*/*/zz_generated.deepcopy.go'], dir='controller/')

docker_build_with_restart(
    'controller:latest', './controller',
    dockerfile_contents=DOCKERFILE,
    entrypoint=['/manager'],
    only=['./bin/manager'],
    live_update=[
        sync('./controller/bin/manager', '/manager'),
    ]
)
