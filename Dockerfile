FROM golang:1.19-alpine@sha256:0ec0646e208ea58e5d29e558e39f2e59fccf39b7bda306cb53bbaff91919eca5 AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY main.go ./
COPY docker/ ./docker/
COPY babashka/ ./babashka/

RUN CGO_ENABLED=0 go build -o pod-atomisthq-tools.docker

FROM alpine:3.17

COPY repository/ /root/.babashka/pods/repository
COPY --from=build /app/pod-atomisthq-tools.docker /root/.babashka/pods/repository/atomisthq/tools.docker/0.1.0
RUN chmod 755 /root/.babashka/pods/repository/atomisthq/tools.docker/0.1.0/pod-atomisthq-tools.docker
