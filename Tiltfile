allow_k8s_contexts(os.environ['TILT_ALLOW_K8S_CONTEXT'])
default_registry(os.environ['TILT_REGISTRY'])

WEBHOOKCERTJOB_DOCKERFILE = '''FROM golang:alpine
WORKDIR /
COPY ./bin/webhookcertjob /
CMD ["/webhookcertjob"]
'''

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
