FROM golang:1.25.9-alpine3.23 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/gcp-token-proxy/ cmd/gcp-token-proxy/
RUN CGO_ENABLED=0 go build -o server ./cmd/gcp-token-proxy

FROM alpine:3.23.4
RUN apk add --no-cache ca-certificates
COPY --from=build /app/server /server
EXPOSE 8080
CMD ["/server"]
