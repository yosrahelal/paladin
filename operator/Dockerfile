# Build the manager binary
FROM golang:1.22 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# We use Dockerfile.dockerignore to make this efficient
COPY . .

# Build
# TODO: Investigate if there is a need for cross-compilation, and if so we need to
#       wait to implement until the domain specific signer plugin interface 
#       is enabled, such that Zeto can remove non-cross-compilable ZKP libs
#       from the core build.
RUN cd operator; go build -a -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/operator/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
