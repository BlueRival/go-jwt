package jwt

import (
	"errors"
	"fmt"
	jwtGo "github.com/dgrijalva/jwt-go"
)

// pass through type
type MapClaims jwtGo.MapClaims

func SignClaims(key string, claims MapClaims) (string, error) {

	tokenForSigning := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, jwtGo.MapClaims(claims))
	return tokenForSigning.SignedString([]byte(key))

}

func ParseClaims(key string, jwtString string) (MapClaims, error) {

	// Parse a JWT, verify it is still valid, and extract the claims
	tokenForParsing, tokenParsingErr := jwtGo.Parse(jwtString, func(token *jwtGo.Token) (interface{}, error) {

		// Apparently you have to manually check the algorithm. Not sure why
		if _, ok := token.Method.(*jwtGo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(key), nil

	})

	if tokenParsingErr != nil {
		return MapClaims{}, tokenParsingErr
	}

	claims, ok := tokenForParsing.Claims.(jwtGo.MapClaims)

	if !ok || !tokenForParsing.Valid {
		return MapClaims{}, errors.New("failed to parse JWT")
	}

	return MapClaims(claims), nil

}
