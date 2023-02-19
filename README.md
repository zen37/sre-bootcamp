## curl
curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "secret"}' http://localhost:8080/login

# Implementation Checklist
- [ ] API Code
- [ ] Services Code
- [ ] Unit-tests
- [ ] Dockerfile
- [ ] It Compiles
- [ ] It runs

# Api Services
- Receives a valid username and password and returns a JWT.
- Returns protected data with a valid token, otherwise returns unauthenticated.