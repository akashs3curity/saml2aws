package saml2aws

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

// AWSAccount holds the AWS account name and roles
type AWSAccount struct {
	Name  string
	Roles []*AWSRole
}

// ParseAWSAccounts extract the aws accounts from the saml assertion
func ParseAWSAccounts(audience string, samlAssertion string) ([]*AWSAccount, error) {
	res, err := http.PostForm(audience, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving AWS login form")
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving AWS login body")
	}

	return ExtractAWSAccounts(data)
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func ExtractAWSAccounts(data []byte) ([]*AWSAccount, error) {
	accounts := []*AWSAccount{}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	b64data, ok := doc.Find("meta[name=data]").Attr("content")
	if !ok {
		return nil, errors.New("failed to find meta[name=data] in AWS response")
	}
	
	// decode the base64 encoded data
	data, err = base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64 data")
	}
	
	type dataResponse struct {
		InvalidAccounts struct{}            `json:"invalid_accounts"`
		RelayState      any                 `json:"RelayState"`
		Name            any                 `json:"name"`
		RolesAccounts   map[string][]string `json:"roles_accounts"`
		ForeignAccounts struct{}            `json:"foreign_accounts"`
		Region          string              `json:"region"`
		Portal          any                 `json:"portal"`
		Problems        string              `json:"problems"`
		Policy          any                 `json:"policy"`
	}
	
	dr := &dataResponse{}
	if err := json.Unmarshal(data, dr); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal data")
	}
	
	// for each account map to our structure
	for account, roles := range dr.RolesAccounts {
		name := strings.TrimSpace(strings.Split(account, "(")[0])
	
		awsAccount := &AWSAccount{
			Name: name,
		}
	
		for _, role := range roles {
			awsRole := &AWSRole{
				Name:    role,
				RoleARN: role,
			}
	
			awsAccount.Roles = append(awsAccount.Roles, awsRole)
		}
	
		accounts = append(accounts, awsAccount)
	}

	return accounts, nil
}

// AssignPrincipals assign principal from roles
func AssignPrincipals(awsRoles []*AWSRole, awsAccounts []*AWSAccount) {

	awsPrincipalARNs := make(map[string]string)
	for _, awsRole := range awsRoles {
		awsPrincipalARNs[awsRole.RoleARN] = awsRole.PrincipalARN
	}

	for _, awsAccount := range awsAccounts {
		for _, awsRole := range awsAccount.Roles {
			awsRole.PrincipalARN = awsPrincipalARNs[awsRole.RoleARN]
		}
	}

}

// LocateRole locate role by name
func LocateRole(awsRoles []*AWSRole, roleName string) (*AWSRole, error) {
	for _, awsRole := range awsRoles {
		if awsRole.RoleARN == roleName {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied RoleArn not found in saml assertion: %s", roleName)
}
