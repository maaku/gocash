# Use the official golang 1.19 bullseye image as the base image
FROM golang:1.19-bullseye AS base

# Set the working directory to /gocash
WORKDIR /gocash

# Throw-away build stage to reduce size of final image
FROM base as build

# Install packages need to build webminer
RUN apt-get update -qq && \
    apt-get install -y build-essential git && \
		rm -rf /var/lib/apt/lists /var/cache/apt/archives

RUN git clone https://github.com/maaku/libsha2

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

# Build webminer
RUN go build -o ./bin/webminer webminer.go

# Final stage
FROM base

# Copy built artifacts: webminer
COPY --from=build /gocash/bin/webminer /webminer

CMD ["/webminer"]