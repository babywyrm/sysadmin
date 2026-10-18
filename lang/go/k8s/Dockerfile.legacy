######################################

FROM arm32v7/golang:alpine AS builder
ADD app.go /go/src/hello/app.go
WORKDIR /go/src/hello
RUN apk add --no-cache gcc libc-dev
RUN GOOS=linux GOARCH=arm GOARM=5 go build app.go

FROM hypriot/rpi-alpine-scratch
COPY --from=builder /go/src/hello/app /app
CMD ["/app"]

######################################
