FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM golang:1.24-alpine
RUN apk --no-cache add ca-certificates git
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/index.html .
EXPOSE 8050
CMD ["./main"]
