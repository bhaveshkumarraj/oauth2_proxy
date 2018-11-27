package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	httpmock "gopkg.in/jarcoal/httpmock.v1"
)

type TestIAM struct {
	Host            string
	AccountId       string
	ApiKey          string
	AccessToken     string
	RefreshToken    string
	TokenExpiration int
	RootUrl         string
}

func testIAM(host string, accountId string, apiKey string) *IAM {
	p := IAM{
		Host:      host,
		AccountId: accountId,
		ApiKey:    apiKey,
	}
	return &p
}

func TestIAMObject(t *testing.T) {
	p := testIAM("localhost", "xxxx", "yyyy")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "localhost", p.Host)
	assert.Equal(t, "xxxx", p.AccountId)
	assert.Equal(t, "yyyy", p.ApiKey)
}

func TestIAMRoles(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://localhost/identity/token",
		httpmock.NewStringResponder(200, `{"access_token": "accesstoken", 
											"refresh_token": "refreshtoken",
											"expiration": 200,
											"token_type": "authorization",
											"expires_in": 100,
											"scope": "profile email"}`))

	p := testIAM("localhost", "xxxx", "yyyy")
	err := p.GetToken()
	assert.Equal(t, err, nil)
	assert.Equal(t, "accesstoken", p.AccessToken)
	assert.Equal(t, "refreshtoken", p.RefreshToken)
	assert.Equal(t, 200, p.TokenExpiration)

	//test PrepareHttpRequest
	httpRequest, err := p.PrepareHttpRequest("https://localhost/identity/token")
	assert.Equal(t, err, nil)
	assert.Equal(t, "accesstoken", httpRequest.Header.Get("Authorization"))

	// test getGroups
	var memberId string = "IBMidxxxxxx"
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://localhost/v1/groups?account="+p.AccountId+"&limit=100&member="+memberId,
		httpmock.NewStringResponder(200, `{"last": {"href": "https://iam.bluemix.net/v1/groups?offset=0&limit=100&account=accountid&member=IBMid-randomstr"}, 
										"total_count": 1, "limit": 100, "groups": [{"href": "https://iam.bluemix.net/v1/groups/AccessGroupId-randomstr", 
										"description": "Editor group for isc-dev-common for Random region", "name": "isc-dev-Random-Common-Editor", 
										"id": "AccessGroupId-randomstr"}], "offset": 0, 
										"first": {"href": "https://iam.bluemix.net/v1/groups?limit=100&account=accountid&member=IBMid-randomstr"}}`))

	iamGroups, err := p.GetGroups(memberId)

	assert.Equal(t, err, nil)
	assert.Equal(t, 1, iamGroups.TotalCount)
	assert.Equal(t, "isc-dev-Random-Common-Editor", iamGroups.Groups[0].Name)

	//test get users
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://localhost/v1/accounts/xxxx/users",
		httpmock.NewStringResponder(200, `{"total_results": 50, "next_url": "",
											"limit": 100, "first_url": "/v1/accounts/accountid/users", "resources": [{"metadata":
											{"url": "/v1/accounts/accountid/users/randomstr", "created_at": "2018-04-11T10:15:43.880Z",
											 "updated_at": "2018-11-04T21:54:29.859Z", "verified_at": "", "linkages": [{"origin": "UAA",
											 "id": "randomid"}, {"origin": "IMS", "id": "imsid"}], "guid": "skldfgklsdjgklj", "identity":
											 {"username": "test.test@ibm.com", "identifier": "454dgdfgdfg", "id": "IBMid-randomstr",
											 "realmid": "IBMid"}}, "entity": {"first_name": "", "iam_id": "IBMid-randomstr",
											 "account_id": "accountid", "photo": "", "state": "PENDING", "last_name": "", "phonenumber": "",
											 "role": "MEMBER", "email": "test.test@ibm.com"}}]}`))

	uamResponse, err := p.GetUsers("localhost")
	assert.Equal(t, err, nil)
	assert.Equal(t, 1, len(uamResponse.Resources))
	assert.Equal(t, "test.test@ibm.com", uamResponse.Resources[0].Entity.Email)
	assert.Equal(t, "IBMid-randomstr", uamResponse.Resources[0].Entity.IAMId)
	assert.Equal(t, 50, uamResponse.TotalResults)

	//test MapEmailsToIAMIds
	emailIAMIdsMap := p.MapEmailsToIAMIds(uamResponse)
	assert.Equal(t, "IBMid-randomstr", emailIAMIdsMap["test.test@ibm.com"])
}
