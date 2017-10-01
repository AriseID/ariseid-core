# Build Idd in a stock Go builder container
FROM golang:1.9-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers

ADD . /ariseid-core
RUN cd /ariseid-core && make idd

# Pull Idd into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /ariseid-core/build/bin/idd /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["idd"]
