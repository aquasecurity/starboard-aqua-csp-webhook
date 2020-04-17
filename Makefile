SOURCES := $(shell find . -name '*.go')
BINARY := webhook
IMAGE_TAG := dev
IMAGE := aquasec/starboard-aqua-csp-webhook:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) cmd/webhook/main.go

docker-build: build
	docker build --no-cache -t $(IMAGE) .
