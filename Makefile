# Config
BINARY=ipanema
VERSION=0.1.2
TARGET=all
BUILD_TIME=`date +%FT%T%z`
LDFLAGS=-ldflags="\
	-s \
	-w \
	-X main.version=${VERSION} \
	-X main.buildTime=${BUILD_TIME}"


.DEFAULT_GOAL: $(BINARY)

.PHONY: all
$(TARGET):
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY}.exe
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY}_darwin
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY}_linux
	tar czvf ${BINARY}_darwin.tgz ${BINARY}_darwin
	tar czvf ${BINARY}_linux.tgz ${BINARY}_linux
	zip -9 ${BINARY}_windows.zip ${BINARY}.exe

.PHONY: macos
macos:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY}
	mv ${BINARY} ${GOBIN}/

.PHONY: clean
clean:
	rm -rf ${BINARY}.exe ${BINARY}_darwin ${BINARY}_linux ${BINARY}_darwin.tgz ${BINARY}_linux.tgz ${BINARY}_windows.zip
