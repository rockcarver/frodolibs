package frodolibs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const amApiVersion string = "resource=1.0"
const idmAdminScope string = "fr:idm:*"
const apiVersion string = "resource=2.0, protocol=1.0"
const realmPathTemplate string = "/realms/%s"

func GetRealmUrl(realm string) string {
	if strings.HasPrefix(realm, "/") && len(realm) > 1 {
		realm = realm[1:len(realm)]
	}
	realmPath := fmt.Sprintf(realmPathTemplate, "root")
	// fmt.Printf("realm: %s\n", realm)
	if realm != "/" {
		realmPath = realmPath + fmt.Sprintf(realmPathTemplate, realm)
	}
	// fmt.Printf("realmpath: %s\n", realmPath)
	return realmPath
	// authURL := fmt.Sprintf("%s/json%s/authenticate", tenant, realmPath)
}

func GetTenantURL(tenant string) string {
	u, err2 := url.Parse(tenant)
	if err2 != nil {
		panic(err2)
	}
	url := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	return url
}

func GetCompleteRedirectURL(tenant string, uri string) string {
	u, err2 := url.Parse(tenant)
	if err2 != nil {
		panic(err2)
	}
	url := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, uri)
	return url
}

func ExtractTokenFromResponse(payload []byte, tokenName string) (string, error) {
	jsonMap := make(map[string](interface{}))
	err := json.Unmarshal([]byte(payload), &jsonMap)
	if err != nil {
		return "", errors.New(fmt.Sprintf("ERROR: fail to unmarshal json, %s", err.Error()))
	}
	tokenValue, err2 := jsonMap[tokenName].(string)
	if err2 {
		return tokenValue, nil
	} else {
		return "", errors.New(fmt.Sprintf("ERROR: no %s found in response", tokenName))
	}
}

var ootbnodetypes_7_1 = map[string]bool{
	"PushRegistrationNode":                   true,
	"GetAuthenticatorAppNode":                true,
	"MultiFactorRegistrationOptionsNode":     true,
	"OptOutMultiFactorAuthenticationNode":    true,
	"AcceptTermsAndConditionsNode":           true,
	"AccountActiveDecisionNode":              true,
	"AccountLockoutNode":                     true,
	"AgentDataStoreDecisionNode":             true,
	"AnonymousSessionUpgradeNode":            true,
	"AnonymousUserNode":                      true,
	"AttributeCollectorNode":                 true,
	"AttributePresentDecisionNode":           true,
	"AttributeValueDecisionNode":             true,
	"AuthLevelDecisionNode":                  true,
	"ChoiceCollectorNode":                    true,
	"ConsentNode":                            true,
	"CookiePresenceDecisionNode":             true,
	"CreateObjectNode":                       true,
	"CreatePasswordNode":                     true,
	"DataStoreDecisionNode":                  true,
	"DeviceGeoFencingNode":                   true,
	"DeviceLocationMatchNode":                true,
	"DeviceMatchNode":                        true,
	"DeviceProfileCollectorNode":             true,
	"DeviceSaveNode":                         true,
	"DeviceTamperingVerificationNode":        true,
	"DisplayUserNameNode":                    true,
	"EmailSuspendNode":                       true,
	"EmailTemplateNode":                      true,
	"IdentifyExistingUserNode":               true,
	"IncrementLoginCountNode":                true,
	"InnerTreeEvaluatorNode":                 true,
	"IotAuthenticationNode":                  true,
	"IotRegistrationNode":                    true,
	"KbaCreateNode":                          true,
	"KbaDecisionNode":                        true,
	"KbaVerifyNode":                          true,
	"LdapDecisionNode":                       true,
	"LoginCountDecisionNode":                 true,
	"MessageNode":                            true,
	"MetadataNode":                           true,
	"MeterNode":                              true,
	"ModifyAuthLevelNode":                    true,
	"OneTimePasswordCollectorDecisionNode":   true,
	"OneTimePasswordGeneratorNode":           true,
	"OneTimePasswordSmsSenderNode":           true,
	"OneTimePasswordSmtpSenderNode":          true,
	"PageNode":                               true,
	"PasswordCollectorNode":                  true,
	"PatchObjectNode":                        true,
	"PersistentCookieDecisionNode":           true,
	"PollingWaitNode":                        true,
	"ProfileCompletenessDecisionNode":        true,
	"ProvisionDynamicAccountNode":            true,
	"ProvisionIdmAccountNode":                true,
	"PushAuthenticationSenderNode":           true,
	"PushResultVerifierNode":                 true,
	"QueryFilterDecisionNode":                true,
	"RecoveryCodeCollectorDecisionNode":      true,
	"RecoveryCodeDisplayNode":                true,
	"RegisterLogoutWebhookNode":              true,
	"RemoveSessionPropertiesNode":            true,
	"RequiredAttributesDecisionNode":         true,
	"RetryLimitDecisionNode":                 true,
	"ScriptedDecisionNode":                   true,
	"SelectIdPNode":                          true,
	"SessionDataNode":                        true,
	"SetFailureUrlNode":                      true,
	"SetPersistentCookieNode":                true,
	"SetSessionPropertiesNode":               true,
	"SetSuccessUrlNode":                      true,
	"SocialFacebookNode":                     true,
	"SocialGoogleNode":                       true,
	"SocialNode":                             true,
	"SocialOAuthIgnoreProfileNode":           true,
	"SocialOpenIdConnectNode":                true,
	"SocialProviderHandlerNode":              true,
	"TermsAndConditionsDecisionNode":         true,
	"TimeSinceDecisionNode":                  true,
	"TimerStartNode":                         true,
	"TimerStopNode":                          true,
	"UsernameCollectorNode":                  true,
	"ValidatedPasswordNode":                  true,
	"ValidatedUsernameNode":                  true,
	"WebAuthnAuthenticationNode":             true,
	"WebAuthnDeviceStorageNode":              true,
	"WebAuthnRegistrationNode":               true,
	"ZeroPageLoginNode":                      true,
	"product-CertificateCollectorNode":       true,
	"product-CertificateUserExtractorNode":   true,
	"product-CertificateValidationNode":      true,
	"product-KerberosNode":                   true,
	"product-ReCaptchaNode":                  true,
	"product-Saml2Node":                      true,
	"product-WriteFederationInformationNode": true,
}

var ootbnodetypes_7 = map[string]bool{
	"AcceptTermsAndConditionsNode":           true,
	"AccountActiveDecisionNode":              true,
	"AccountLockoutNode":                     true,
	"AgentDataStoreDecisionNode":             true,
	"AnonymousSessionUpgradeNode":            true,
	"AnonymousUserNode":                      true,
	"AttributeCollectorNode":                 true,
	"AttributePresentDecisionNode":           true,
	"AttributeValueDecisionNode":             true,
	"AuthLevelDecisionNode":                  true,
	"ChoiceCollectorNode":                    true,
	"ConsentNode":                            true,
	"CookiePresenceDecisionNode":             true,
	"CreateObjectNode":                       true,
	"CreatePasswordNode":                     true,
	"DataStoreDecisionNode":                  true,
	"DeviceGeoFencingNode":                   true,
	"DeviceLocationMatchNode":                true,
	"DeviceMatchNode":                        true,
	"DeviceProfileCollectorNode":             true,
	"DeviceSaveNode":                         true,
	"DeviceTamperingVerificationNode":        true,
	"DisplayUserNameNode":                    true,
	"EmailSuspendNode":                       true,
	"EmailTemplateNode":                      true,
	"IdentifyExistingUserNode":               true,
	"IncrementLoginCountNode":                true,
	"InnerTreeEvaluatorNode":                 true,
	"IotAuthenticationNode":                  true,
	"IotRegistrationNode":                    true,
	"KbaCreateNode":                          true,
	"KbaDecisionNode":                        true,
	"KbaVerifyNode":                          true,
	"LdapDecisionNode":                       true,
	"LoginCountDecisionNode":                 true,
	"MessageNode":                            true,
	"MetadataNode":                           true,
	"MeterNode":                              true,
	"ModifyAuthLevelNode":                    true,
	"OneTimePasswordCollectorDecisionNode":   true,
	"OneTimePasswordGeneratorNode":           true,
	"OneTimePasswordSmsSenderNode":           true,
	"OneTimePasswordSmtpSenderNode":          true,
	"PageNode":                               true,
	"PasswordCollectorNode":                  true,
	"PatchObjectNode":                        true,
	"PersistentCookieDecisionNode":           true,
	"PollingWaitNode":                        true,
	"ProfileCompletenessDecisionNode":        true,
	"ProvisionDynamicAccountNode":            true,
	"ProvisionIdmAccountNode":                true,
	"PushAuthenticationSenderNode":           true,
	"PushResultVerifierNode":                 true,
	"QueryFilterDecisionNode":                true,
	"RecoveryCodeCollectorDecisionNode":      true,
	"RecoveryCodeDisplayNode":                true,
	"RegisterLogoutWebhookNode":              true,
	"RemoveSessionPropertiesNode":            true,
	"RequiredAttributesDecisionNode":         true,
	"RetryLimitDecisionNode":                 true,
	"ScriptedDecisionNode":                   true,
	"SelectIdPNode":                          true,
	"SessionDataNode":                        true,
	"SetFailureUrlNode":                      true,
	"SetPersistentCookieNode":                true,
	"SetSessionPropertiesNode":               true,
	"SetSuccessUrlNode":                      true,
	"SocialFacebookNode":                     true,
	"SocialGoogleNode":                       true,
	"SocialNode":                             true,
	"SocialOAuthIgnoreProfileNode":           true,
	"SocialOpenIdConnectNode":                true,
	"SocialProviderHandlerNode":              true,
	"TermsAndConditionsDecisionNode":         true,
	"TimeSinceDecisionNode":                  true,
	"TimerStartNode":                         true,
	"TimerStopNode":                          true,
	"UsernameCollectorNode":                  true,
	"ValidatedPasswordNode":                  true,
	"ValidatedUsernameNode":                  true,
	"WebAuthnAuthenticationNode":             true,
	"WebAuthnDeviceStorageNode":              true,
	"WebAuthnRegistrationNode":               true,
	"ZeroPageLoginNode":                      true,
	"product-CertificateCollectorNode":       true,
	"product-CertificateUserExtractorNode":   true,
	"product-CertificateValidationNode":      true,
	"product-KerberosNode":                   true,
	"product-ReCaptchaNode":                  true,
	"product-Saml2Node":                      true,
	"product-WriteFederationInformationNode": true,
}

var ootbnodetypes_6_5 = map[string]bool{
	"AbstractSocialAuthLoginNode":          true,
	"AccountLockoutNode":                   true,
	"AgentDataStoreDecisionNode":           true,
	"AnonymousUserNode":                    true,
	"AuthLevelDecisionNode":                true,
	"ChoiceCollectorNode":                  true,
	"CookiePresenceDecisionNode":           true,
	"CreatePasswordNode":                   true,
	"DataStoreDecisionNode":                true,
	"InnerTreeEvaluatorNode":               true,
	"LdapDecisionNode":                     true,
	"MessageNode":                          true,
	"MetadataNode":                         true,
	"MeterNode":                            true,
	"ModifyAuthLevelNode":                  true,
	"OneTimePasswordCollectorDecisionNode": true,
	"OneTimePasswordGeneratorNode":         true,
	"OneTimePasswordSmsSenderNode":         true,
	"OneTimePasswordSmtpSenderNode":        true,
	"PageNode":                             true,
	"PasswordCollectorNode":                true,
	"PersistentCookieDecisionNode":         true,
	"PollingWaitNode":                      true,
	"ProvisionDynamicAccountNode":          true,
	"ProvisionIdmAccountNode":              true,
	"PushAuthenticationSenderNode":         true,
	"PushResultVerifierNode":               true,
	"RecoveryCodeCollectorDecisionNode":    true,
	"RecoveryCodeDisplayNode":              true,
	"RegisterLogoutWebhookNode":            true,
	"RemoveSessionPropertiesNode":          true,
	"RetryLimitDecisionNode":               true,
	"ScriptedDecisionNode":                 true,
	"SessionDataNode":                      true,
	"SetFailureUrlNode":                    true,
	"SetPersistentCookieNode":              true,
	"SetSessionPropertiesNode":             true,
	"SetSuccessUrlNode":                    true,
	"SocialFacebookNode":                   true,
	"SocialGoogleNode":                     true,
	"SocialNode":                           true,
	"SocialOAuthIgnoreProfileNode":         true,
	"SocialOpenIdConnectNode":              true,
	"TimerStartNode":                       true,
	"TimerStopNode":                        true,
	"UsernameCollectorNode":                true,
	"WebAuthnAuthenticationNode":           true,
	"WebAuthnRegistrationNode":             true,
	"ZeroPageLoginNode":                    true,
}

var ootbnodetypes_6 = map[string]bool{
	"AbstractSocialAuthLoginNode":          true,
	"AccountLockoutNode":                   true,
	"AgentDataStoreDecisionNode":           true,
	"AnonymousUserNode":                    true,
	"AuthLevelDecisionNode":                true,
	"ChoiceCollectorNode":                  true,
	"CookiePresenceDecisionNode":           true,
	"CreatePasswordNode":                   true,
	"DataStoreDecisionNode":                true,
	"InnerTreeEvaluatorNode":               true,
	"LdapDecisionNode":                     true,
	"MessageNode":                          true,
	"MetadataNode":                         true,
	"MeterNode":                            true,
	"ModifyAuthLevelNode":                  true,
	"OneTimePasswordCollectorDecisionNode": true,
	"OneTimePasswordGeneratorNode":         true,
	"OneTimePasswordSmsSenderNode":         true,
	"OneTimePasswordSmtpSenderNode":        true,
	"PageNode":                             true,
	"PasswordCollectorNode":                true,
	"PersistentCookieDecisionNode":         true,
	"PollingWaitNode":                      true,
	"ProvisionDynamicAccountNode":          true,
	"ProvisionIdmAccountNode":              true,
	"PushAuthenticationSenderNode":         true,
	"PushResultVerifierNode":               true,
	"RecoveryCodeCollectorDecisionNode":    true,
	"RecoveryCodeDisplayNode":              true,
	"RegisterLogoutWebhookNode":            true,
	"RemoveSessionPropertiesNode":          true,
	"RetryLimitDecisionNode":               true,
	"ScriptedDecisionNode":                 true,
	"SessionDataNode":                      true,
	"SetFailureUrlNode":                    true,
	"SetPersistentCookieNode":              true,
	"SetSessionPropertiesNode":             true,
	"SetSuccessUrlNode":                    true,
	"SocialFacebookNode":                   true,
	"SocialGoogleNode":                     true,
	"SocialNode":                           true,
	"SocialOAuthIgnoreProfileNode":         true,
	"SocialOpenIdConnectNode":              true,
	"TimerStartNode":                       true,
	"TimerStopNode":                        true,
	"UsernameCollectorNode":                true,
	"WebAuthnAuthenticationNode":           true,
	"WebAuthnRegistrationNode":             true,
	"ZeroPageLoginNode":                    true,
}
