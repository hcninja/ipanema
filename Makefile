# Config
BINARY=ipanema
VERSION=0.1.1
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
	mkdir deploy
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o build/${BINARY}.exe
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o build/${BINARY}_darwin
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o build/${BINARY}_linux
	cd deploy
	tar czvf ${BINARY}_darwin.tgz ${BINARY}_darwin
	tar czvf ${BINARY}_linux.tgz ${BINARY}_linux
	zip -9 ipanema_windows.zip ipanema.exe

.PHONY: macos
macos:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY}
	mv ${BINARY} ${GOBIN}/

.PHONY: clean
clean:
	rm -rf build
