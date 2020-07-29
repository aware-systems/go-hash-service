# go-hash-service
Password hashing service

This project is the result of a test project for Jumpcloud.

## Summary:
A simple hashing REST service.  You can compile and run the service
through typical go means:

```
$ go run go-hash-service.go --port 8080 --address localhost
```

Port and address are optional command line arguments.  Service will run
in the foreground of your terminal until either Ctrl-C or the shutdown
request is received.

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

## Misc.
This software is distributed under the MIT license.  See the accompanying
LICENSE file for more information.

Created July 2020 by Adam Erickson, adam@awre.co

