package openid

import (
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	json "github.com/json-iterator/go"
	"github.com/simonnilsson/ask"
	log "github.com/sirupsen/logrus"
	"github.com/thoas/go-funk"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"strings"
	"sync"
)

const DiscoveryPath = ".well-known/openid-configuration"

type OIDCMiddleware struct {
	config    *Config
	provider  *oidc.Provider
	oauthConf oauth2.Config
	store     sync.Map
}

func New(ctx context.Context, conf *Config) *OIDCMiddleware {
	provider, providerErr := oidc.NewProvider(ctx, conf.IssuerURL)
	if providerErr != nil {
		log.Fatalf("[OIDC] - Failed initializing provider: %v", providerErr)
	}
	oauth2Conf := oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  conf.RedirectURL,
		Scopes:       conf.Scopes,
	}
	return &OIDCMiddleware{
		config:    conf,
		provider:  provider,
		oauthConf: oauth2Conf,
		store:     sync.Map{},
	}
}

func (s *OIDCMiddleware) HandleAuth(c *fiber.Ctx) error {
	var authHeader = c.Get(fiber.HeaderAuthorization)
	var isNotCallback = c.Path() != s.GetCallbackPath()
	var hasAuthHeader = funk.NotEmpty(authHeader)
	var hasBearerToken = strings.HasPrefix(authHeader, "Bearer")
	var rawToken = strings.TrimPrefix(authHeader, "Bearer ")
	var isJWT = strings.HasPrefix(rawToken, "ey")

	switch {
	case !hasAuthHeader && isNotCallback:
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Error{
			Code:    fiber.StatusUnauthorized,
			Message: "Access Denied",
		})

	case hasAuthHeader && hasBearerToken && isNotCallback:
		if !isJWT {
			return c.JSON(fiber.Error{
				Code:    401,
				Message: "Unauthorized",
			})
		}

		var discoveryURL = fmt.Sprintf("%s/%s", s.config.IssuerURL, DiscoveryPath)
		var idpConfig, idpErr = fetchOpenIDConfiguration(discoveryURL)
		if idpErr != nil {
			log.Errorf("[OIDC] - Failed to fetch OpenID configuration: %v", idpErr)
			return c.JSON(fiber.Error{
				Code:    500,
				Message: idpErr.Error(),
			})
		}

		var token, tokenErr = jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("[OIDC] - Unexpected signing method: %v", token.Header["alg"])
			}

			jwks, jwksErr := fetchJWKS(idpConfig.JwksURI)
			if jwksErr != nil {
				fmt.Println("[OIDC] - Failed to fetch JWKS:", jwksErr)
				return nil, jwksErr
			}

			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("[OIDC] - missing kid in token header")
			}

			key, err := findKey(jwks, kid)
			if err != nil {
				return nil, err
			}

			return convertJWKSKeyToPEM(key)
		})
		if tokenErr != nil {
			log.Errorf("[OIDC] - Failed parsing JWT: %v", tokenErr)
			return c.JSON(fiber.Error{
				Code:    401,
				Message: "Unauthorized",
			})
		}

		audience, err := token.Claims.GetAudience()
		if err != nil {
			return c.JSON(fiber.Error{
				Code:    401,
				Message: "Unauthorized",
			})
		}

		// ServiceAccount auth ends here
		if containsAny(s.config.ServiceAccounts, audience) {
			return c.Next()
		}

		req, reqErr := http.NewRequest(http.MethodGet, idpConfig.UserInfoEndpoint, nil)
		if reqErr != nil {
			log.Errorf("[OIDC] - Failed creating request: %v", reqErr)
			return c.JSON(fiber.Error{
				Code:    401,
				Message: "Unauthorized",
			})
		}

		req.Header.Add(fiber.HeaderAuthorization, fmt.Sprintf("Bearer %s", token.Raw))

		var result map[string]interface{}

		var resp, respErr = http.DefaultClient.Do(req)
		if respErr != nil {
			log.Errorf("[OIDC] - Failed fetching user info: %v", respErr)
			return c.JSON(fiber.Error{
				Code:    401,
				Message: "Unauthorized",
			})
		}

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return c.JSON(fiber.Error{
				Code:    401,
				Message: "Unauthorized",
			})
		}

		var decErr = json.NewDecoder(resp.Body).Decode(&result)
		if decErr != nil {
			log.Errorf("[OIDC] - Failed decoding user info: %v", decErr)
			return c.JSON(fiber.Error{
				Code: 401,
			})
		}

		groupsContainer, ok := ask.For(result, "groups").Slice(nil)
		if ok {
			groups, _ := interfaceToStringSlice(groupsContainer)
			if containsAny(s.config.Groups, groups) {
				return c.Next()
			}
		}
	}
	return c.Status(401).JSON(fiber.Error{
		Code:    401,
		Message: "UNAUTHORIZED",
	})
}

func (s *OIDCMiddleware) RedirectToIDP(c *fiber.Ctx) error {
	var state = generateID()
	var codeVerifier = generateID()
	var idpAuthURL = s.oauthConf.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))

	s.store.Store(state, codeVerifier)

	return c.Redirect(idpAuthURL)
}

func (s *OIDCMiddleware) HandleCallback(c *fiber.Ctx) error {
	var code = c.Query("code")
	var state = c.Query("state")
	var codeVerifier, ok = s.store.Load(state)
	if !ok {
		return c.Status(401).JSON(fiber.Error{
			Code:    401,
			Message: "Failed logging in",
		})
	}
	oauth2Token, err := s.oauthConf.Exchange(c.Context(),
		code,
		oauth2.S256ChallengeOption(codeVerifier.(string)),
		oauth2.VerifierOption(codeVerifier.(string)))
	if err != nil {
		return c.Status(401).JSON(fiber.Error{
			Code:    401,
			Message: "Failed logging in: " + err.Error(),
		})
	}

	return c.JSON(oauth2Token)
}

func (s *OIDCMiddleware) GetCallbackPath() string {
	return strings.ReplaceAll(s.config.RedirectURL, s.config.BaseURL, "")
}
