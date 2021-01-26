FROM golang:1.15

# WORKDIR /src

COPY main.go .

RUN go get -d -v ./...
RUN go build -o main .

# ENTRYPOINT ["/bin/bash"]

# CMD ["/main"]

CMD ["go run ."]