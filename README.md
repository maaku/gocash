# gocash

Webcash implementation in Go 

## Getting Started

### Installation

1. Clone the repo

```sh
git clone https://github.com/maaku/gocash.git
```

2. Update submodules
```sh
git submodule update --init
```

3. Get packages and dependencies
```sh
go get
```

4. Build webminer
```sh
go build -o bin/webminer webminer.go
```

5. Have fun!

### Docker

1. Build image
```sh
docker build -t gocash .
```


## Usage

```sh
./bin/webminer
```

### Docker

```sh
docker run -it --rm -v "$PWD:/gocash" --name webminer gocash
```