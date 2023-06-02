FROM golang:1.20-buster

RUN apt-get update && apt-get -y install libunbound-dev && apt-get -y clean

WORKDIR /letsdebug

CMD make clean letsdebug-server
