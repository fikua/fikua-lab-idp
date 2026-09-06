FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/idp ./cmd/idp

FROM scratch
# Needed for outbound HTTPS to the Credential Issuer (issuance records,
# claim metadata) — this service makes outbound TLS calls, so it can't
# skip CA certs.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/idp /idp
EXPOSE 8080
ENTRYPOINT ["/idp"]
