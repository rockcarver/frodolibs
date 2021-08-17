package frodolibs

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-resty/resty/v2"
	cv "github.com/jimlambrt/go-oauth-pkce-code-verifier"
)

const adminClientPassword string = "doesnotmatter"
const serverInfoURLTemplate string = "%s/json/serverinfo/%s"
const authorizeURLTemplate string = "%s/oauth2%s/authorize"
const accessTokenURLTemplate string = "%s/oauth2%s/access_token"
const redirectURLTemplate string = "/platform/appAuthHelperRedirect.html"
const oauthClientURLTemplate string = "%s/json%s/realm-config/agents/OAuth2Client/%s"

var verbose bool = true
var authCode = ""
var versionString string

// var deploymentType string

var adminClientId string = "idmAdminClient"

type FRToken struct {
	tenant         string
	realm          string
	cookieName     string
	tokenId        string
	bearerToken    string
	deploymentType string
	version        string
}

func NewFRToken(tenant string, realm string) FRToken {
	if realm == "" {
		realm = "/"
	}
	frt := FRToken{tenant: tenant, realm: realm, cookieName: "", tokenId: "", bearerToken: "", deploymentType: "", version: ""}
	// fmt.Printf("%s, %s, %s, %s, %s, %s\n", frt.tenant, frt.realm, frt.cookieName, frt.tokenId, frt.bearerToken, frt.version)
	return frt
}

func (frt *FRToken) GetTokenId() string {
	// fmt.Printf("%s, %s, %s, %s, %s, %s\n", frt.tenant, frt.realm, frt.cookieName, frt.tokenId, frt.bearerToken, frt.version)
	return frt.tokenId
}
func (frt *FRToken) GetBearerToken() string {
	return frt.bearerToken
}
func (frt *FRToken) GetDeploymentType() string {
	return frt.deploymentType
}
func (frt *FRToken) GetVersion() string {
	return frt.version
}

func (frt *FRToken) DetermineDeployment() error {
	// cookieName, _ := GetCookieName(frt.tenant)
	fidcClientId := "idmAdminClient"
	forgeopsClientId := "idm-admin-ui"

	// try to get fidcClientId first
	client := resty.New()
	resp1, err1 := client.R().
		SetHeader("Accept-API-Version", amApiVersion).
		SetCookie(&http.Cookie{Name: frt.cookieName, Value: frt.tokenId}).
		Get(fmt.Sprintf(oauthClientURLTemplate, frt.tenant, "/alpha", fidcClientId))
	if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
		if resp1.StatusCode() == 404 {
			// not found - try for forgeopsClientId
			resp2, err2 := client.R().
				SetHeader("Accept-API-Version", amApiVersion).
				SetCookie(&http.Cookie{Name: frt.cookieName, Value: frt.tokenId}).
				Get(fmt.Sprintf(oauthClientURLTemplate, frt.tenant, "", forgeopsClientId))
			if resp2.StatusCode() < 200 || resp2.StatusCode() > 399 {
				if resp2.StatusCode() == 404 {
					// not found, its on-prem
					fmt.Printf("No known OAuth clients found, likely classic deployment\n")
					frt.deploymentType = "Classic"
				}
			} else {
				if err2 == nil {
					fmt.Printf("%s found, likely ForgeOps deployment\n", forgeopsClientId)
					adminClientId = forgeopsClientId
					frt.deploymentType = "ForgeOps"
				} else {
					// log.Printf("Error %s\n", err1.Error())
					return errors.New(fmt.Sprintf("ERROR: error determining deployment: %s\n", err2.Error()))
				}
			}
		} else {
			// log.Printf("Error %d\n", resp1.StatusCode())
			return errors.New(fmt.Sprintf("ERROR: determine deployment call returned %d", resp1.StatusCode()))
		}
	} else {
		if err1 == nil {
			fmt.Printf("%s found, likely ForgeRock ID Cloud\n", fidcClientId)
			frt.deploymentType = "Cloud"
		} else {
			// log.Printf("Error %s\n", err1.Error())
			return errors.New(fmt.Sprintf("ERROR: error determining deployment: %s\n", err1.Error()))
		}
	}
	return nil
}

func (frt *FRToken) GetVersionInfo() error {
	// cookieName, _ := GetCookieName(tenant)

	client := resty.New()
	resp1, err1 := client.R().
		SetHeader("Accept-API-Version", amApiVersion).
		SetCookie(&http.Cookie{Name: frt.cookieName, Value: frt.tokenId}).
		Get(fmt.Sprintf(serverInfoURLTemplate, frt.tenant, "version"))

	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return errors.New(fmt.Sprintf("ERROR: get version call returned %d", resp1.StatusCode()))
		}
		jsonMap := make(map[string](interface{}))
		responseBody := resp1.Body()
		// log.Printf("resp: %s", responseBody)
		err2 := json.Unmarshal([]byte(responseBody), &jsonMap)
		if err2 != nil {
			return errors.New(fmt.Sprintf("ERROR: fail to unmarshal json: %s", err2.Error()))
		}
		version := jsonMap["version"].(string)

		re := regexp.MustCompile(`([\d]\.[\d]\.[\d](\.[\d])*)`)

		versionString = fmt.Sprintf("%s", re.Find([]byte(version)))
		log.Printf("version: %s\n", versionString)
		frt.version = versionString
		fullVersion := jsonMap["fullVersion"]
		fmt.Printf("Connected to %s\n", fullVersion)
		return nil
	} else {
		// log.Printf("ERROR: error getting version info: %s\n", err1.Error())
		return errors.New(fmt.Sprintf("ERROR: error getting version info: %s\n", err1.Error()))
	}
}

func (frt *FRToken) GetCookieName() error {
	client := resty.New()
	resp1, err1 := client.R().Get(fmt.Sprintf(serverInfoURLTemplate, frt.tenant, "*"))

	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return errors.New(fmt.Sprintf("ERROR: get cookie call returned %d", resp1.StatusCode()))
		}
		jsonMap := make(map[string](interface{}))
		err2 := json.Unmarshal([]byte(resp1.Body()), &jsonMap)
		if err2 != nil {
			return errors.New(fmt.Sprintf("ERROR: fail to unmarshal json, %s", err2.Error()))
		}
		cookieName := jsonMap["cookieName"].(interface{})
		frt.cookieName = cookieName.(string)
		return nil
	} else {
		return errors.New(fmt.Sprintf("ERROR: error getting cookie name, %s\n", err1.Error()))
	}
}

func AuthCodeExtractRedirectPolicy() resty.RedirectPolicy {
	fn := resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		queryString, _ := url.ParseQuery(req.URL.RawQuery)
		// log.Println(queryString)
		authCode = queryString["code"][0]
		// log.Printf("authCode: %s\n", authCode)
		return nil
	})

	return fn
}

func (frt *FRToken) GetAccessToken() error {

	v, _ := cv.CreateCodeVerifier()
	codeVerifier := v.String()

	codeChallenge := v.CodeChallengeS256()
	codeChallengeMethod := "S256"

	// the authorize and access_token urls always are root realms when admin tokens are needed
	authorizeURL := fmt.Sprintf(authorizeURLTemplate, frt.tenant, "/")
	accessTokenURL := fmt.Sprintf(accessTokenURLTemplate, frt.tenant, "/")
	redirectURL := GetCompleteRedirectURL(frt.tenant, redirectURLTemplate)
	// cookieName, _ := GetCookieName(frt.tenant)

	err := frt.GetAuthCode(authorizeURL, redirectURL, codeChallenge, codeChallengeMethod)
	if err != nil {
		return errors.New(fmt.Sprintf("ERROR: error getting access token"))
	}

	client := resty.New()
	// client.SetRedirectPolicy(AuthCodeExtractRedirectPolicy())
	// client.SetDebug(true)
	var resp1 *resty.Response
	var err1 error
	if frt.deploymentType == "Cloud" {
		client.SetBasicAuth(adminClientId, adminClientPassword)
		resp1, err1 = client.R().
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetFormData(map[string]string{
				"redirect_uri":  redirectURL,
				"grant_type":    "authorization_code",
				"code":          authCode,
				"code_verifier": codeVerifier,
			}).
			Post(accessTokenURL)
	} else {
		resp1, err1 = client.R().
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetFormData(map[string]string{
				"client_id":     adminClientId,
				"redirect_uri":  redirectURL,
				"grant_type":    "authorization_code",
				"code":          authCode,
				"code_verifier": codeVerifier,
			}).
			Post(accessTokenURL)
	}

	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return errors.New(fmt.Sprintf("ERROR: access token call returned %d\n", resp1.StatusCode()))
		}
		accessToken, err2 := ExtractTokenFromResponse(resp1.Body(), "access_token")
		if err2 == nil {
			// log.Printf("access token: %s", accessToken)
			frt.bearerToken = accessToken
			return nil
		} else {
			return errors.New(fmt.Sprintf("ERROR: can not extract access token from response, %s\n", err2.Error()))
		}
	} else {
		return errors.New(fmt.Sprintf("ERROR: access token call failed, %s\n", err1.Error()))
	}
}

func (frt *FRToken) GetAuthCode(authorizeURL string, redirectURL string, codeChallenge string, codeChallengeMethod string) error {
	client := resty.New()
	client.SetRedirectPolicy(AuthCodeExtractRedirectPolicy())
	// client.SetDebug(true)
	resp1, err1 := client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"redirect_uri":          redirectURL,
			"scope":                 idmAdminScope,
			"response_type":         "code",
			"client_id":             adminClientId,
			"csrf":                  frt.tokenId,
			"decision":              "allow",
			"code_challenge":        codeChallenge,
			"code_challenge_method": codeChallengeMethod,
		}).
		SetCookie(&http.Cookie{
			Name:  frt.cookieName,
			Value: frt.tokenId,
		}).
		Post(authorizeURL)

	// log.Printf("resp1: %s", resp1)

	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return errors.New(fmt.Sprintf("ERROR: authorize call returned %d\nlikely cause: mismatched parameters with OAuth client config", resp1.StatusCode()))
		}
		return nil
	} else {
		return errors.New(fmt.Sprintf("ERROR: authorize call failed, %s\n", err1.Error()))
	}
}

func CheckAndSkip2FA(payload []byte) (string, error) {
	jsonMap := make(map[string](interface{}))
	err := json.Unmarshal([]byte(payload), &jsonMap)
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: fail to unmarshal json, %s", err.Error()))
	}

	callbacks, exists := jsonMap["callbacks"].([]interface{})
	if exists {
		for index, _ := range callbacks {
			callbackMap := callbacks[index].(map[string]interface{})
			// fmt.Printf("callback: %s\n", callbackMap["type"])
			if callbackMap["type"].(string) == "HiddenValueCallback" {
				inputs := callbackMap["input"].([]interface{})
				firstInput := inputs[0].(map[string]interface{})
				if strings.Contains(firstInput["value"].(string), "skip") {
					firstInput["value"] = "Skip"
				}
			}
		}
		updatedJsonString, err := json.Marshal(jsonMap)
		if err != nil {
			return "", errors.New(fmt.Sprintf("ERROR: fail to marshal json, %s\n", err.Error()))
		}
		// fmt.Printf("INFO: updatedJsonString %s\n", updatedJsonString)
		return string(updatedJsonString), nil
	} else {
		// 2FA callback not found, likely there is no 2FA and we have the token
		return string(payload), errors.New(fmt.Sprintf("NO2FA"))
	}
}

func (frt *FRToken) Authenticate(username string, password string) error {

	frt.GetCookieName()

	client := resty.New()
	// client.SetDebug(true)
	// realm for authentication is always "/"
	authURL := fmt.Sprintf("%s/json%s/authenticate", frt.tenant, GetRealmUrl("/"))
	// fmt.Printf("%s\n", authURL)
	resp1, err1 := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept-API-Version", apiVersion).
		SetHeader("X-OpenAM-Username", username).
		SetHeader("X-OpenAM-Password", password).
		SetBody("{}").
		Post(authURL)

	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return errors.New(fmt.Sprintf("ERROR: first authenticate call returned %d\nlikely cause: wrong username or password", resp1.StatusCode()))
		}
		newPayload, err2 := CheckAndSkip2FA(resp1.Body())
		if err2 == nil {
			resp2, err3 := client.R().
				SetHeader("Content-Type", "application/json").
				SetHeader("Accept-API-Version", apiVersion).
				SetBody(newPayload).
				Post(authURL)
			if resp2.StatusCode() < 200 || resp2.StatusCode() > 399 {
				return errors.New(fmt.Sprintf("ERROR: skip 2FA call returned %d\nlikely cause: 2FA skipping not possible, or skip callback changed", resp2.StatusCode()))
			}
			if err3 == nil {
				// log.Printf("cookies: %s", resp2.Cookies())
				tokenId, err4 := ExtractTokenFromResponse(resp2.Body(), "tokenId")
				if err4 == nil {
					frt.tokenId = tokenId
					frt.GetVersionInfo()
					frt.DetermineDeployment()
					// fmt.Printf("%s, %s, %s, %s, %s, %s\n", frt.tenant, frt.realm, frt.cookieName, frt.tokenId, frt.bearerToken, frt.version)
					return nil
				} else {
					return errors.New(fmt.Sprintf("ERROR: can not extract tokenId from response, %s\n", err4.Error()))
				}
			} else {
				return errors.New(fmt.Sprintf("ERROR: second authenticate call failed, %s\n", err3.Error()))
			}
		} else {
			if err2.Error() == "NO2FA" {
				// 2FA is not needed - most likely non-cloud deployment
				tokenId, err4 := ExtractTokenFromResponse([]byte(newPayload), "tokenId")
				if err4 == nil {
					frt.tokenId = tokenId
					frt.GetVersionInfo()
					frt.DetermineDeployment()
					return nil
				} else {
					return errors.New(fmt.Sprintf("ERROR: can not extract tokenId from response, %s\n", err4.Error()))
				}
			} else {
				return errors.New(fmt.Sprintf("ERROR: error checking for 2FA, %s\n", err2.Error()))
			}
		}
	} else {
		return errors.New(fmt.Sprintf("ERROR: first authenticate call failed, %s\n", err1.Error()))
	}
}
