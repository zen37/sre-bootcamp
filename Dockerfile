# Use the official golang image as the base image
FROM golang:1.17.5-alpine3.15 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the source code to the container
COPY . .

# Build the Go program
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Create a new, smaller image to reduce the final image size
FROM alpine:3.15

# Copy the built Go program from the builder image to the new image
COPY --from=builder /app/main .

# Set the command to run when the container starts
CMD [ "./main" ]
