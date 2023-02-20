
https://github.com/wizelineacademy/sre-bootcamp

## curl
curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:8000/login


export TOKEN=$(curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:8000/login | jq -r '.token')
curl -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" http://localhost:8000/protected --verbose




# Implementation Checklist
- [X] API Code
- [X] Services Code
- [X] Unit-tests
- [X] Dockerfile
- [X] It Compiles
- [X] It runs

# Api Services
- Receives a valid username and password and returns a JWT.
- Returns protected data with a valid token, otherwise returns unauthenticated.