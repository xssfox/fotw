Rough code notes

### Static content
Bootstrap site. Really only `index.html` and `js.js`
Very minimal JS to support posting to api gateway.

### lambda_function
Contains both functions in a single python module. 

### `ca.pem` 
is from `https://sourceforge.net/p/trustedqsl/tqsl/ci/master/tree/src/location.cpp#l308`. In theory we should check the root as well (I have), however since its not included in the log, we'd need to package both the intermediate (`ca.pem`) and (`root.pem`) so why bother.

Is this an issue if the cert expires? No because the cert is already expired.

### test_lambda_function.py
Some basic tests are provided in `test_lambda_function.py`

### Infra
Currently clickops because eh, whatever.

- two lambda functions
    - docker image
    - env var - SECRET - must be 10 chars longer
    - command override
        - lambda_function.validate
        - lambda_function.verify
- s3 bucket - oac policy
- api gateway
    - GET /check/{callsign}/{timestamp}/{code} -> lambda_function.validate
    - PUSH /verify -> lambda_function.verify
    - cors enabled but probably doesn't need to be - makes API testing easier
- cloudfront
    - cache policy - 1 second - used for check/* specifically
    - path patterns
        - verify -> api gateway
        - check/* -> api gateway
        - everything else -> s3
    - oac to s3 bucket
