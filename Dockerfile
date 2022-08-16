FROM golang:1.19-buster

RUN apt-get update && apt-get -y install libunbound-dev && apt-get -y clean

WORKDIR /letsdebug

CMD make deps letsdebug-server
