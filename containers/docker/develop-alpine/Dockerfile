FROM alpine:3.5

RUN \
  apk add --update go git make gcc musl-dev linux-headers ca-certificates && \
  git clone --depth 1 https://github.com/ariseid/ariseid-core && \
  (cd AriseID && make idd) && \
  cp AriseID/build/bin/idd /idd && \
  apk del go git make gcc musl-dev linux-headers && \
  rm -rf /ariseid-core && rm -rf /var/cache/apk/*

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/idd"]
