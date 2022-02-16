FROM golang:1.17.7-buster

RUN apt-get update && apt-get -y install libunbound-dev && apt-get -y clean

WORKDIR /letsdebug

CMD make deps letsdebug-server