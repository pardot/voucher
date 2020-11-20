FROM golang:1.15-buster as build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
WORKDIR /app
RUN go install -v .


FROM debian:buster

WORKDIR /app

RUN apt-get update && \
    apt-get install -y awscli && \
    rm -rf /var/lib/apt/lists/*

COPY capture-metadata-traffic.sh /usr/bin/capture-metadata-traffic.sh

COPY --from=build /go/bin/voucher /usr/bin/voucher

CMD ["./voucher"]
