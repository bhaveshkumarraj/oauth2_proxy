package providers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
)

type OIDCProvider struct {
	*ProviderData

	Verifier *oidc.IDTokenVerifier
}

func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

func (p *OIDCProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("id_token did not contain an email")
	}
	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	s = &SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresOn:    token.Expiry,
		Email:        claims.Email,
	}

	return
}

func (p *OIDCProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn
	s.ExpiresOn = time.Now().Add(time.Second).Truncate(time.Second)
	fmt.Printf("refreshed access token %s (expired on %s)\n", s, origExpiration)
	return false, nil
}

func (p *OIDCProvider) SetUserRoles(iamConfig map[string]string) ([]string, error) {

	iam := IAM{
		Host:      iamConfig["IAMHost"],
		AccountId: iamConfig["IAMAccountId"],
		ApiKey:    iamConfig["IAMAPIKey"],
	}

	// TODO: Need try catch here
	iam.GetToken()
	uamUsers, _ := iam.GetUsers(iamConfig["UAMHost"])
	emailIAMIdsMap := iam.MapEmailsToIAMIds(uamUsers)
	iamId := emailIAMIdsMap[iamConfig["Email"]]

	if iamId == "" {
		return nil, errors.New("IAM roles doesn't exist.")
	}

	iamGroups, _ := iam.GetGroups(iamId)

	var roles []string

	if len(iamGroups.Groups) == 0 {
		return []string{"unknown"}, nil
	}

	for _, group := range iamGroups.Groups {
		roles = append(roles, group.Name)
	}

	log.Printf("Setting user roles: %s", roles)
	return roles, nil
}

func (p *OIDCProvider) GetUserRoles() string {
	// return strings.Join(p.userRoles, ",")
	return ""
}
