FROM scratch

COPY webhook /webhook

ENTRYPOINT ["/webhook"]
