API_SRC = ${PWD}/cmd/api/main.go
API_BIN = ${PWD}/bin/dummyci-api

build-api:
	go build -o ${API_BIN} ${API_SRC}

run-api:
	${API_BIN}

clean-api:
	rm -rf ${API_BIN}

dev-api:
	go run ${API_SRC}
