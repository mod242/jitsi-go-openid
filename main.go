package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

type Config struct {
	JitsiSecret   string `mapstructure:"JITSI_SECRET"`
	JitsiURL      string `mapstructure:"JITSI_URL"`
	JitsiSub      string `mapstructure:"JITSI_SUB"`
	IssuerBaseURL string `mapstructure:"ISSUER_BASE_URL"`
	BaseURL       string `mapstructure:"BASE_URL"`
	ClientID      string `mapstructure:"CLIENT_ID"`
	Secret        string `mapstructure:"SECRET"`
	Prejoin       bool   `mapstructure:"PREJOIN"`
	Deeplink      bool   `mapstructure:"DEEPLINK"`
	NameKey       string `mapstructure:"NAME_KEY"`
}

var config Config

type PlayLoad struct {
	ID    string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"-"`
}

func (p *PlayLoad) UnmarshalJSON(data []byte) error {
	var aux struct {
		ID    string `json:"sub,omitempty"`
		Email string `json:"email,omitempty"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.ID = aux.ID
	p.Email = aux.Email

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if name, ok := m[config.NameKey].(string); ok {
		p.Name = name
	}
	return nil
}

type UserContext struct {
	User struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("Found no .env-File, will use Environment Variables")
	}

	config.JitsiSecret = os.Getenv("JITSI_SECRET")
	config.JitsiURL = os.Getenv("JITSI_URL")
	config.JitsiSub = os.Getenv("JITSI_SUB")
	config.IssuerBaseURL = os.Getenv("ISSUER_BASE_URL")
	config.BaseURL = os.Getenv("BASE_URL")
	config.ClientID = os.Getenv("CLIENT_ID")
	config.Secret = os.Getenv("SECRET")
	config.Prejoin, _ = strconv.ParseBool(os.Getenv("PREJOIN"))
	config.Prejoin = config.Prejoin || false
	config.Deeplink, _ = strconv.ParseBool(os.Getenv("DEEPLINK"))
	config.Deeplink = config.Deeplink || true
	config.NameKey = os.Getenv("NAME_KEY")
	if config.NameKey == "" {
		config.NameKey = "name"
	}
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func main() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.IssuerBaseURL)
	if err != nil {
		log.Fatal("Error when trying to connect to OICD Provider", err)
	}

	oauthConfig := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.Secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.Trim(config.BaseURL, "/") + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	r := gin.Default()
	r.SetTrustedProxies(nil)

	r.GET("/authenticate", func(c *gin.Context) {
		jitsiState := c.Query("state")
		room := c.Query("room")
		var data map[string]interface{}
		err := json.Unmarshal([]byte(jitsiState), &data)
		if err != nil {
			log.Println("Error analyzing JSON from State:", err)
			return
		}

		client := "browser"
		if val, ok := data["electron"].(bool); ok && val {
			client = "electron"
		} else if val, ok := data["ios"].(bool); ok && val {
			client = "ios"
		} else if val, ok := data["android"].(bool); ok && val {
			client = "android"
		}

		state, err := randString(16)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		nonce, err := randString(16)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		stateData := map[string]interface{}{
			"originalState": state,
			"client":        client,
		}

		stateJSON, err := json.Marshal(stateData)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		encodedState := base64.RawURLEncoding.EncodeToString(stateJSON)
		c.SetCookie("state", encodedState, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		c.SetCookie("nonce", nonce, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		c.SetCookie("room", room, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		c.Redirect(http.StatusFound, oauthConfig.AuthCodeURL(encodedState, oidc.Nonce(nonce)))
	})

	r.GET("/callback", func(c *gin.Context) {
		stateDataEncoded, err := c.Cookie("state")
		if err != nil {
			c.String(http.StatusInternalServerError, "state not found")
			return
		}

		if c.Query("state") != stateDataEncoded {
			c.String(http.StatusInternalServerError, "state did not match")
			return
		}

		c.SetCookie("state", "", -1, "/", "", c.Request.TLS != nil, true)
		nonce, err := c.Cookie("nonce")
		if err != nil {
			c.String(http.StatusInternalServerError, "nonce not found")
			return
		}

		room, err := c.Cookie("room")
		if err != nil {
			c.String(http.StatusInternalServerError, "state not set")
			return
		}

		c.SetCookie("room", "", -1, "/", "", c.Request.TLS != nil, true)
		oauth2Token, err := oauthConfig.Exchange(ctx, c.Query("code"))
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to exchange token: %v", err))
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			c.String(http.StatusInternalServerError, "No id_token field in oauth2 token.")
			return
		}

		oidcConfig := &oidc.Config{
			ClientID: config.ClientID,
		}

		verifier := provider.Verifier(oidcConfig)
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to verify ID Token: %v", err))
			return
		}

		if idToken.Nonce != nonce {
			c.String(http.StatusBadRequest, "nonce did not match")
			return
		}

		c.SetCookie("nonce", "", -1, "/", "", c.Request.TLS != nil, true)
		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		var playLoad PlayLoad
		err = json.Unmarshal(*resp.IDTokenClaims, &playLoad)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		user := &UserContext{}
		user.User.Email = playLoad.Email
		user.User.Name = playLoad.Name

		stateJSON, err := base64.RawURLEncoding.DecodeString(stateDataEncoded)
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to decode state")
			return
		}

		var stateData map[string]interface{}
		err = json.Unmarshal(stateJSON, &stateData)
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to parse state")
			return
		}

		claims := jwt.MapClaims{}
		claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix()
		claims["aud"] = "jitsi"
		claims["sub"] = config.JitsiSub
		claims["iss"] = "jitsi"
		claims["room"] = room
		claims["context"] = user

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(config.JitsiSecret))
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		jitsiURL, err := url.Parse(config.JitsiURL)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Invalid Jitsi URL: %v", err))
			return
		}

		jitsiURL.Path = path.Join(jitsiURL.Path, room)
		if config.Deeplink {
			switch stateData["client"].(string) {
			case "electron":
				jitsiURL.Scheme = "jitsi-meet"
			case "ios":
				jitsiURL.Scheme = "org.jitsi.meet"
			case "android":
				jitsiURL.Scheme = "org.jitsi.meet"
			}
		}

		q := jitsiURL.Query()
		q.Set("jwt", tokenString)
		jitsiURL.RawQuery = q.Encode()
		if !config.Prejoin {
			jitsiURL.Fragment = "config.prejoinConfig.enabled=false"
		}

		log.Println("Redirect Url:", jitsiURL.String())
		c.Redirect(http.StatusFound, jitsiURL.String())
	})

	r.Run(":3001")
}
