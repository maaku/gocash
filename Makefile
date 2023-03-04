# Set the target operating system and architecture
GOOS=windows
GOARCH=amd64
CC=x86_64-w64-mingw32-gcc

all: build winbuild

build: webminer.go
	go build -o bin/webminer webminer.go

winbuild: webminer.go
	CC=$(CC) CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o bin/webminer.exe webminer.go

clean:
	rm bin/webminer.exe
	rm bin/webminer

run:
	export WINEPATH="/usr/x86_64-w64-mingw32/lib;/usr/lib/gcc/x86_64-w64-mingw32/7.3-posix" && \
	export WINEPREFIX=~/.wine64 && \
	export WINEARCH=win64 && \
	wine bin/webminer.exe


