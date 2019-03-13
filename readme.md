# Go JWT Library

This library provides basic JWT functionality for Go. The purpose of the library is to provide a standard signing 
mechanism and format for signing and validating JWT claims payloads at Charter. In order to maintain simplicity the 
library expose three items: A claims data type, and two methods for signing and parsing a JWT.

## Exported Resources

`type MapClaims map[string]interface{}` 
This data type is required for creating a claims object to storing data in a signed JWT.

`func SignClaims(key string, claims MapClaims) (string, error)`
Provide a pre-shared key and a claims instance. The string response is a JWT suitable for returning to a client request.

`func ParseClaims(key string, jwtString string) (MapClaims, error)` 
Provide a pre-shared key and a JWT string. The claims response will be the claims in the JWT, if the JWT signature is 
valid. Otherwise claims will be an empty instance and error response will be non-nil.


## Pre-Shared Key Security

This library does not enforce a secure pre-shared key. You could use empty string. It is up to the code consuming this 
library to agree to standards for pre-shared key length and complexity patterns.


## Release Notes

### This release

v0.0.1 - Initial Release

### Previous releases

None
