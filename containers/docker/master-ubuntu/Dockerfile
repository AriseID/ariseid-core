FROM ubuntu:xenial

RUN \
  apt-get update && apt-get upgrade -q -y && \
  apt-get install -y --no-install-recommends golang git make gcc libc-dev ca-certificates && \
  git clone --depth 1 --branch release/1.7 https://github.com/ariseid/ariseid-core && \
  (cd AriseID && make idd) && \
  cp AriseID/build/bin/idd /idd && \
  apt-get remove -y golang git make gcc libc-dev && apt autoremove -y && apt-get clean && \
  rm -rf /ariseid-core

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/idd"]
