FROM golang
COPY . /go
WORKDIR /go/src/github.com/chitchat
RUN go get github.com/lib/pq
RUN go install github.com/chitchat
ENTRYPOINT /go/bin/chitchat
EXPOSE 8080