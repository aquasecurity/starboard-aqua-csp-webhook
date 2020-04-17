SOURCES := $(shell find . -name '*.go')
BINARY := webhook
IMAGE_TAG := dev
IMAGE := aquasec/starboard-aqua-csp-webhook:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -mod=vendor -o $(BINARY) cmd/webhook/main.go

test: $(SOURCES)
	GO111MODULE=on go test -mod=vendor -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

docker-build: build
	docker build --no-cache -t $(IMAGE) .
