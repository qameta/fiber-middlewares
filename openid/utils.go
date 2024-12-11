package openid

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"io"
	"math/big"
	"net/http"
	"strings"

	json "github.com/json-iterator/go"
)

type JWKSConfiguration struct {
	JwksURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

type JWKSKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func generateID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func fetchOpenIDConfiguration(openIDConfigURL string) (*JWKSConfiguration, error) {
	resp, err := http.Get(openIDConfigURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: %s", resp.Status)
	}

	var config JWKSConfiguration
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func convertJWKSKeyToPEM(jwksKey *JWKSKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwksKey.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus (n): %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwksKey.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent (e): %v", err)
	}

	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	rsaPubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	return rsaPubKey, nil
}

func fetchJWKS(jwksURL string) (*JWKS, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	return &jwks, nil
}

func findKey(jwks *JWKS, kid string) (*JWKSKey, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

func interfaceToStringSlice(input []interface{}) ([]string, error) {
	result := make([]string, len(input))
	for i, v := range input {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a string", i)
		}
		result[i] = str
	}
	return result, nil
}

func containsAny(slice1, slice2 []string) bool {
	set := make(map[string]struct{})
	for _, v := range slice2 {
		set[v] = struct{}{}
	}

	for _, v := range slice1 {
		if _, exists := set[v]; exists {
			return true
		}
	}
	return false
}
