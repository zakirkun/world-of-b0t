package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// The signing secret. Deliberately a single, common dictionary word so it can
// be recovered with hashcat/john + rockyou against a captured token.
// ponytail: hardcoded on purpose - the weakness IS the challenge.
const jwtSecret = "nightwatch"

var errBadToken = errors.New("invalid token")

type claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(data string, secret string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(data))
	return m.Sum(nil)
}

// issue builds an HS256 JWT. Only HS256 is ever produced.
func issue(c claims) (string, error) {
	header := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := header + "." + b64(payload)
	return signingInput + "." + b64(sign(signingInput, jwtSecret)), nil
}

// verify parses and validates a JWT.
//
// SECURITY NOTE (intentional): we ONLY accept alg=="HS256". A token carrying
// alg="none" (or any other alg) is rejected outright, so the alg:none shortcut
// does not work here - the intended path is cracking the weak secret and
// forging a correctly-SIGNED admin token. Verified with hmac.Equal to avoid
// timing leaks, and compared as raw bytes.
func verify(tok string) (claims, error) {
	var c claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c, errBadToken
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, errBadToken
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return c, errBadToken
	}
	if hdr.Alg != "HS256" {
		// Explicitly refuse alg:none and every non-HS256 algorithm.
		return c, errBadToken
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, errBadToken
	}
	want := sign(parts[0]+"."+parts[1], jwtSecret)
	if !hmac.Equal(sig, want) {
		return c, errBadToken
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errBadToken
	}
	if err := json.Unmarshal(pb, &c); err != nil {
		return c, errBadToken
	}
	return c, nil
}
