package jwt

import (
	"encoding/json"
	"strings"
	"testing"
	jwtGo "github.com/dgrijalva/jwt-go"
)

func TestValid(t *testing.T) {

	key := "a key"

	myJWT, jwtErr := SignClaims(key, MapClaims{
		"Some": "Value",
	})

	if jwtErr != nil {
		t.Error("SignClaims error should be nil")
	}

	claims, claimsErr := ParseClaims(key, myJWT)

	if claimsErr != nil {
		t.Error("ParseClaims error should be nil")
	}

	if claims["Some"] != "Value" {
		t.Error("claims should have correct data")
	}

}

func TestBadKey(t *testing.T) {

	key := "a key"

	myJWT, jwtErr := SignClaims(key, MapClaims{
		"Some": "Value",
	})

	if jwtErr != nil {
		t.Error("SignClaims error should be nil")
	}

	claims, claimsErr := ParseClaims(key+"bad key", myJWT)

	if claimsErr == nil {
		t.Error("ParseClaims error should NOT be nil")
	} else if claimsErr.Error() != "signature is invalid" {
		t.Error("ParseClaims error should have value signature is invalid")
	}

	if claims["Some"] == "Value" {
		t.Error("claims should NOT have data")
	}

}

func TestHeader(t *testing.T) {

	key := "a key"

	myJWT, jwtErr := SignClaims(key, MapClaims{
		"Some": "Value",
	})

	if jwtErr != nil {
		t.Error("SignClaims error should be nil")
		return;
	}

	myJWTParts := strings.Split(myJWT, ".")

	header, _ := jwtGo.DecodeSegment(myJWTParts[0])

	type HeaderMap struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}

	headerMap := HeaderMap{}

	jsonUnmarshalErr := json.Unmarshal(header, &headerMap)

	if jsonUnmarshalErr != nil {
		t.Error("failed to parse header segment: " + jsonUnmarshalErr.Error())
		return
	}

	if headerMap.Alg != "HS256" {
		t.Error("header algorithm is wrong: " + headerMap.Alg)
		return
	}

	if headerMap.Typ != "JWT" {
		t.Error("header type is wrong: " + headerMap.Typ)
		return
	}

	headerMap.Alg = "ES256"

	header, jsonMarshalErr := json.Marshal(headerMap)

	if jsonMarshalErr != nil {
		t.Error("Failed to marshal header: " + jsonMarshalErr.Error())
		return
	}

	myJWTParts[0] = jwtGo.EncodeSegment(header)

	myJWT = strings.Join(myJWTParts, ".")

	claims, claimsErr := ParseClaims(key, myJWT)

	if claimsErr == nil {
		t.Error("ParseClaims error should NOT be nil")
		return
	} else if claimsErr.Error() != "Unexpected signing method: ES256" {
		t.Error("ParseClaims error should have value Unexpected signing method: ES256")
		return
	}

	if claims["Some"] == "Value" {
		t.Error("claims should NOT have data")
		return
	}

}

func TestPayload(t *testing.T) {

	key := "a key"

	myJWT, jwtErr := SignClaims(key, MapClaims{
		"Some": "Value",
	})

	if jwtErr != nil {
		t.Error("SignClaims error should be nil")
		return;
	}

	myJWTParts := strings.Split(myJWT, ".")

	payload, _ := jwtGo.DecodeSegment(myJWTParts[1])

	var payloadMap map[string]string

	jsonUnmarshalErr := json.Unmarshal(payload, &payloadMap)

	if jsonUnmarshalErr != nil {
		t.Error("failed to parse payload segment: " + jsonUnmarshalErr.Error())
		return
	}

	if payloadMap["Some"] != "Value" {
		t.Error("payload value is wrong: " + payloadMap["Some"])
		return
	}

	payloadMap["Some"] = "Values"

	payload, jsonMarshalErr := json.Marshal(payloadMap)

	if jsonMarshalErr != nil {
		t.Error("Failed to marshal payload: " + jsonMarshalErr.Error())
		return
	}

	myJWTParts[1] = jwtGo.EncodeSegment(payload)

	myJWT = strings.Join(myJWTParts, ".")

	claims, claimsErr := ParseClaims(key, myJWT)

	if claimsErr == nil {
		t.Error("ParseClaims error should NOT be nil")
		return
	} else if claimsErr.Error() != "signature is invalid" {
		t.Error("ParseClaims error should have value: signature is invalid")
		return
	}

	if claims["Some"] == "Value" {
		t.Error("claims should NOT have data")
		return
	}

}
