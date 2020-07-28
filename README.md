# go-hash-service
Password hashing service

This project is the result of a test project for Jumpcloud.

## Synopse
A simple hashing service.  To be run on the command line like this:

go run go-hash-service.go --port 8080 --address localhost

### hash
Accepts POST to /hash URI, expects password form-encoded parameter.
Responds with an ID number to be referenced later.

Accepts GET to /hash/<ID> presents Base64-encoded SHA512 password
from previous POST request.  ID supplied here must match output 
from above POST.

### stats
Accepts GET to /stats, revealing the number of hashes generated and
the average response time for inital POST request.

### shutdown
Accepts any request to /shutdown to gracefully terminate the server.
NOTE: Windows is less than graceful.

## Usage
Accepts two parameters:
* port - Which port to listen on (default 8080)
* address - Which host to listen on (default localhost)
