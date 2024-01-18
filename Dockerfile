##############################################################
## Stage 1 - Go Build
##############################################################

FROM golang:1.21.4-alpine AS builder

#RUN apk update && apk add --no-cache bash

#RUN apk add gcc

# RUN apk add --no-cache sqlite-libs sqlite-dev

RUN apk add --no-cache build-base

ADD . /go/src/github.com/yunkon-kim/knock-knock

WORKDIR /go/src/github.com/yunkon-kim/knock-knock/cmd/knock-knock

# NOTE - "make prod" executes the commannd, "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o knock-knock"
RUN make prod

#############################################################
## Stage 2 - Application Setup
##############################################################

FROM ubuntu:22.04 as prod

# use bash
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

WORKDIR /app

# Assets
COPY --from=builder /go/src/github.com/yunkon-kim/knock-knock/web/assets/ /app/web/assets/
COPY --from=builder /go/src/github.com/yunkon-kim/knock-knock/web/templates/ /app/web/templates/
COPY --from=builder /go/src/github.com/yunkon-kim/knock-knock/web/fonts/ /app/web/fonts/
COPY --from=builder /go/src/github.com/yunkon-kim/knock-knock/pkg/api/rest/docs/ /app/pkg/api/rest/docs/

# Binary
COPY --from=builder /go/src/github.com/yunkon-kim/knock-knock/cmd/knock-knock/knock-knock /app/

## Set system endpoints
ENV KNOCKKNOCK_ROOT /app

#RUN /bin/bash -c "source /app/conf/setup.env"
## Logger configuration
# Set log file path (default logfile path: ./knock-knock.log) 
ENV LOGFILE_PATH knock-knock.log
ENV LOGFILE_MAXSIZE 10
ENV LOGFILE_MAXBACKUPS 3
ENV LOGFILE_MAXAGE 30
ENV LOGFILE_COMPRESS false
# Set log level, such as trace, debug info, warn, error, fatal, and panic
ENV LOGLEVEL info
# Set log writer, such as file, stdout, or both
ENV LOGWRITER both
# Set execution environment, such as development or production
ENV NODE_ENV production

## Set internal DB config (SQLlite)
ENV DB_URL localhost:3306
ENV DB_DATABASE knock_knock
ENV DB_USER knock_knock
ENV DB_PASSWORD knock_knock

## Set API access config
# API_ALLOW_ORIGINS (ex: https://cloud-barista.org,xxx.xxx.xxx.xxx or * for all)
ENV API_ALLOW_ORIGINS *
# Set ENABLE_AUTH=true currently for basic auth for all routes (i.e., url or path)
ENV API_AUTH_ENABLED true
ENV API_USERNAME default
ENV API_PASSWORD default

## Set period for auto control goroutine invocation
ENV AUTOCONTROL_DURATION_MS 10000

## Set SELF_ENDPOINT, to access Swagger API dashboard outside (Ex: export SELF_ENDPOINT=x.x.x.x:8056)
ENV SELF_ENDPOINT localhost:8056

## Environment variables that you don't need to touch
# Swagger UI API document file path 
ENV APIDOC_PATH /app/pkg/api/rest/docs/swagger.json

ENTRYPOINT [ "/app/knock-knock" ]

EXPOSE 8056
EXPOSE 8888