# build stage
FROM golang:1.25-alpine AS build

RUN apk add --no-cache build-base libpcap-dev linux-headers

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/bettercap-wifi .

# final stage
FROM alpine:3.22

RUN apk add --no-cache ca-certificates libpcap iw wireless-tools iproute2

COPY --from=build /out/bettercap-wifi /usr/local/bin/bettercap-wifi

EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/bettercap-wifi"]
# the API defaults to 127.0.0.1, which is unreachable from outside the container
CMD ["-api-address", "0.0.0.0:8081"]
