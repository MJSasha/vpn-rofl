FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM golang:1.24-alpine
RUN apk --no-cache add ca-certificates git openssh-client
# Разрешаем git работать в директории, даже если владелец отличается
RUN git config --global --add safe.directory /app
WORKDIR /app
# Копируем всё содержимое, включая .git, для работы автообновления
COPY --from=builder /app /app
EXPOSE 8050
CMD ["./main"]
