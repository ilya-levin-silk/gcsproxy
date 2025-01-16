FROM gcr.io/distroless/base
COPY bin/gcsproxy /gcsproxy
ENTRYPOINT ["/gcsproxy"]
