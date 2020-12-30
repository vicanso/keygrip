.PHONY: test test-cover hooks

lint:
	golangci-lint run

# for test
test:
	go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

bench:
	go test -bench=. ./...

hooks:
	cp hooks/* .git/hooks/
