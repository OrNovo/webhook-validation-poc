FROM golang

RUN mkdir /rfolder
COPY . /rfolder

WORKDIR "/rfolder"

RUN go mod tidy
RUN go build main.go

CMD ["go","run","/rfolder/main.go"]