# Один образ на всю сеть: директория, узлы и клиент — один и тот же бинарник.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/xray-onion .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY --from=build /out/xray-onion /usr/local/bin/xray-onion
COPY lab/node-entrypoint.sh /node-entrypoint.sh
RUN chmod +x /node-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/xray-onion"]
