.PHONY: generate build docker-build docker-push deploy clean test

IMAGE_NAME ?= ebpf-netmon
IMAGE_TAG ?= latest
REGISTRY ?= your-registry

generate:
	go generate ./...

build: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/netmon .

docker-build:
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

docker-push: docker-build
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

deploy:
	kubectl apply -f daemonset.yaml

undeploy:
	kubectl delete -f daemonset.yaml

logs:
	kubectl logs -n network-monitoring -l app=ebpf-netmon -f

clean:
	rm -rf bin/
	rm -f bpf_*_bpfe*.go bpf_*_bpfe*.o

test:
	go test -v ./...

scan:
	trivy image $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

lint:
	golangci-lint run