package providers

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"

	api "github.com/bhaveshkumarraj/oauth2_proxy/api"
)

type IAM struct {
	Host            string
	AccountId       string
	ApiKey          string
	AccessToken     string
	RefreshToken    string
	TokenExpiration int
	RootUrl         string
}

type IAMResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiration   int    `json:"expiration"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type IAMGroup struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Href        string `json:"href"`
}

type IAMAccessGroupsResponse struct {
	Offset      int               `json:"offset"`
	Limit       int               `json:"limit"`
	TotalCount  int               `json:"total_count"`
	First       map[string]string `json:"first"`
	Last        map[string]string `json:"last"`
	Description string            `json:"description"`
	Groups      []IAMGroup        `json:"groups"`
}

type UAMIdentity struct {
	Id         string `json:"id"`
	RealmId    string `json:"realmid"`
	Identifier string `json:"identifier"`
	Username   string `json:"username"`
}

type UAMLinkages struct {
	Origin string `json:"origin"`
	Id     string `json:"id"`
}

type UAMMetadata struct {
	Guid       string        `json:"guid"`
	Url        string        `json:"url"`
	CreatedAt  string        `json:"created_at"`
	UpdatedAt  string        `json:"updated_at"`
	VerifiedAt string        `json:"verified_at"`
	Identity   UAMIdentity   `json:"identity"`
	Linkages   []UAMLinkages `json:"linkages"`
}

type UAMEntity struct {
	AccountId   string `json:"account_id"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	State       string `json:"sate"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phonenumber"`
	Role        string `json:"role"`
	Photo       string `json:"photo"`
	IAMId       string `json:"iam_id"`
}

type UAMResources struct {
	Metadata UAMMetadata `json:"metadata"`
	Entity   UAMEntity   `json:"entity"`
}

type UAMUsersResponse struct {
	TotalResults int            `json:"total_results"`
	Limit        int            `json:"limit"`
	FirstUrl     string         `json:"first_url"`
	NextUrl      string         `json:"next_url"`
	Resources    []UAMResources `json:"resources"`
}

type Json struct {
	data interface{}
}

func (idt *IAM) PrepareHttpRequest(apiPath string) (request *http.Request, err error) {
	var req *http.Request
	req, err = http.NewRequest("GET", apiPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "oauth2proxy")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", idt.AccessToken)
	return req, err
}

func (idt *IAM) GetToken() (err error) {

	idt.RootUrl = "https://" + idt.Host
	token_url := idt.RootUrl + "/identity/token"

	params := url.Values{}
	params.Add("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	params.Add("response_type", "cloud_iam")
	params.Add("apikey", idt.ApiKey)

	var req *http.Request
	req, err = http.NewRequest("POST", token_url, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var data IAMResponse
	api.RequestJson(req, &data) // TODO; problem in unmarshalling data.ExpiresIn getting 0 always

	//setting auth info
	idt.AccessToken = data.AccessToken
	idt.RefreshToken = data.RefreshToken
	idt.TokenExpiration = data.Expiration

	return err
}

func (idt *IAM) GetGroups(memberId string) (iamGroups IAMAccessGroupsResponse, err error) {
	apiPath := idt.RootUrl + "/v1/groups?account=" + idt.AccountId + "&limit=100"
	if memberId != "" {
		apiPath += "&member=" + memberId
	}
	req, err := idt.PrepareHttpRequest(apiPath)
	var data IAMAccessGroupsResponse
	api.RequestJson(req, &data)

	lastUrl := data.Last["href"]
	resultsRetrieved := (data.Offset + 1) * data.Limit

	for (data.TotalCount > resultsRetrieved) && lastUrl != "" {
		var tempData IAMAccessGroupsResponse

		//get next batch of the data
		req, err = idt.PrepareHttpRequest(lastUrl)
		api.RequestJson(req, &tempData)

		data.First["href"] = tempData.First["href"]
		data.Last["href"] = tempData.Last["href"]
		data.Offset = tempData.Offset
		data.Groups = append(data.Groups, tempData.Groups...)
	}
	return data, err
}

func (idt *IAM) GetUsers(host string) (uamResponse UAMUsersResponse, err error) {
	rootUrl := "https://" + host
	apiPath := rootUrl + "/v1/accounts/" + idt.AccountId + "/users"

	req, err := idt.PrepareHttpRequest(apiPath)
	var data UAMUsersResponse
	api.RequestJson(req, &data)

	for data.NextUrl != "" {
		var tempData UAMUsersResponse

		//modify url here for the next batch of the data
		req, err = idt.PrepareHttpRequest(rootUrl + data.NextUrl)
		api.RequestJson(req, &tempData)

		data.FirstUrl = tempData.FirstUrl
		data.NextUrl = tempData.NextUrl
		data.Resources = append(data.Resources, tempData.Resources...)
	}
	return data, err
}

func (idt *IAM) MapEmailsToIAMIds(uamResponse UAMUsersResponse) map[string]string {
	emailIAMIdsMap := make(map[string]string)
	for _, resource := range uamResponse.Resources {
		emailIAMIdsMap[strings.ToLower(resource.Entity.Email)] = resource.Entity.IAMId
	}
	return emailIAMIdsMap
}
