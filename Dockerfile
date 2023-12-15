FROM golang:bookworm

RUN apt-get update && apt-get -y install libunbound-dev && apt-get -y clean

WORKDIR /letsdebug

CMD make clean letsdebug-server
