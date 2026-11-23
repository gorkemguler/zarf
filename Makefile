BINARY := zarf
VERSION := 0.1.0

.PHONY: build test vet demo samples serve app release clean

build:
	go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/zarf

test:
	go test -v -race ./...

vet:
	go vet ./...

samples: build
	./$(BINARY) demo --export-dir samples

demo: build
	./$(BINARY) demo --sample homoglyph-cred-phish

serve: build
	./$(BINARY) serve

app: build
	./$(BINARY) app

release:
	bash scripts/build-release.sh $(VERSION)

clean:
	rm -rf $(BINARY) dist
