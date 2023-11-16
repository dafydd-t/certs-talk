This repo contains some example code used in a talk about TLS and SSH certificates.

Generate certs with

```
go run ./cmd/gencert/
```

Run a server using host certs with

```
go run ./cmd/tlsserver
```

Run a client using client certs with

```
go run ./cmd/tlsclient
```
