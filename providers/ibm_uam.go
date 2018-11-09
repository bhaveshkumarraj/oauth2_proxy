package providers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	api "../api"
)

type UAM struct {
	Host            string
	AccountId       string
	ApiKey          string
	AccessToken     string
	RefreshToken    string
	TokenExpiration int
	RootUrl         string
}

type UAMResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiration   int    `json:"expiration"`
	TokenType    string `"json:token_type"`
	ExpiresIn    int    `"json:expires_in"`
	Scope        string `"json:scope"`
}

func (idt *UAM) GetToken() (string, err error) {

	idt.RootUrl = "https://" + idt.Host
	token_url := idt.RootUrl + "/identity/token"

	params := url.Values{}
	params.Add("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	params.Add("response_type", "cloud_iam")
	params.Add("apikey", idt.ApiKey)

	var req *http.Request
	req, err = http.NewRequest("POST", token_url, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var data IAMResponse
	api.RequestJson(req, &data) // TODO; problem in unmarshalling data.ExpiresIn getting 0 always

	//setting auth info
	idt.AccessToken = data.AccessToken
	idt.RefreshToken = data.RefreshToken
	idt.TokenExpiration = data.Expiration

	return
}

func (idt *UAM) GetUsers() (string, err error) {

	apiPath := idt.RootUrl + "/v1/accounts/" + idt.AccountId + "/users"

	var req *http.Request
	req, err = http.NewRequest("GET", apiPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "oauth2proxy")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", idt.AccessToken)

	var data interface{}
	api.RequestJson(req, &data)

	fmt.Println(data)

	return
}
