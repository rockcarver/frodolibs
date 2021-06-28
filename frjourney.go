package frodolibs

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	// "log"
	"net/http"
	"github.com/go-resty/resty/v2"
)

const journeyURLTemplate string = "%s/json%s/realm-config/authentication/authenticationtrees/trees/%s"
const nodeURLTemplate string = "%s/json%s/realm-config/authentication/authenticationtrees/nodes/%s/%s"
const scriptURLTemplate string = "%s/json%s/scripts/%s"
const emailTemplateURLTemplate string = "%s/openidm/config/emailTemplate/%s"
const queryAllTreesURLTemplate string = "%s/json%s/realm-config/authentication/authenticationtrees/trees?_queryFilter=true"

var containerNodes = map[string]bool{
    "PageNode": true,
    "CustomPageNode": true,
}

var scriptedNodes = map[string]bool{
    "ScriptedDecisionNode": true,
    "ClientScriptNode": true,
	"CustomScriptNode": true,
}

var emailTemplateNodes = map[string]bool{
    "EmailSuspendNode": true,
    "EmailTemplateNode": true,
}

func GetNodeData(tenant string, tokenId string, realm string, id string, nodeType string) ([]byte, error) {
	var b []byte

	cookieName, _ := GetCookieName(tenant)
	// log.Printf("Cookie name: %s\n", cookieName)
	client := resty.New()
	// client.SetDebug(true)
	jURL := fmt.Sprintf(nodeURLTemplate, tenant, GetRealmUrl(realm), nodeType, id)
	// log.Printf("url: %s\n", jURL)
	resp1, err1 := client.R().
		SetHeader("Accept-API-Version", amApiVersion).
		SetHeader("X-Requested-With", "XmlHttpRequest").
		SetCookie(&http.Cookie{Name: cookieName, Value: tokenId,}).
		Get(jURL)
	// log.Printf("resp1: %s\n", resp1)
	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return b, errors.New(fmt.Sprintf("ERROR: get node call returned %d, possible cause: node not found", resp1.StatusCode()))
		} else {
			// exports := []byte(`{"origin":"$ORIGIN", "innernodes":{}, "nodes":{}, "scripts":{}, "emailTemplates":{}}`)
			jsonMap := make(map[string](interface{}))
			err := json.Unmarshal([]byte(resp1.Body()), &jsonMap)
			if err != nil {
				return b, errors.New(fmt.Sprintf("ERROR: fail to unmarshal json: %s", err.Error()))
			}
			return resp1.Body(), nil
		}
	} else {
		return b, errors.New(fmt.Sprintf("ERROR: error getting node, %s\n", err1.Error()))
	}
}

func GetTreeData(tenant string, tokenId string, realm string, name string) ([]byte, error) {
	var b []byte
	client := resty.New()
	// client.SetDebug(true)
	jURL := fmt.Sprintf(journeyURLTemplate, tenant, GetRealmUrl(realm), name)
	// log.Printf("url: %s\n", jURL)
	cookieName, _ := GetCookieName(tenant)
	// read tree object
	resp, err := client.R().
		SetHeader("Accept-API-Version", amApiVersion).
		SetHeader("X-Requested-With", "XmlHttpRequest").
		SetCookie(&http.Cookie{Name: cookieName, Value: tokenId,}).
		Get(jURL)
	// log.Printf("resp1: %s\n", resp1.Body())
	if err == nil {
		if resp.StatusCode() < 200 || resp.StatusCode() > 399 {
			return b, errors.New(fmt.Sprintf("ERROR: export journey call returned %d, possible cause: tree not found", resp.StatusCode()))
		} else {
			return resp.Body(), nil
		}
	} else {
		return b, errors.New(fmt.Sprintf("ERROR: get tree data error: %s", err.Error()))
	}
}

func GetScriptData(tenant string, tokenId string, realm string, id string) ([]byte, error) {
	var b []byte

	cookieName, _ := GetCookieName(tenant)
	// log.Printf("Cookie name: %s\n", cookieName)

	client := resty.New()
	// client.SetDebug(true)
	jURL := fmt.Sprintf(scriptURLTemplate, tenant, GetRealmUrl(realm), id)
	// log.Printf("url: %s\n", jURL)
	resp1, err1 := client.R().
		SetHeader("Accept-API-Version", amApiVersion).
		SetHeader("X-Requested-With", "XmlHttpRequest").
		SetCookie(&http.Cookie{Name: cookieName, Value: tokenId,}).
		Get(jURL)
	// log.Printf("resp1: %s\n", resp1)
	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return b, errors.New(fmt.Sprintf("ERROR: get script call returned %d, possible cause: script not found", resp1.StatusCode()))
		} else {
			// exports := []byte(`{"origin":"$ORIGIN", "innernodes":{}, "nodes":{}, "scripts":{}, "emailTemplates":{}}`)
			jsonMap := make(map[string](interface{}))
			err := json.Unmarshal([]byte(resp1.Body()), &jsonMap)
			if err != nil {
				return b, errors.New(fmt.Sprintf("ERROR: fail to unmarshal json, %s", err.Error()))
			}
			return resp1.Body(), nil
		}
	} else {
		return b, errors.New(fmt.Sprintf("ERROR: error getting script, %s\n", err1.Error()))
	}
}

func GetScriptDataAsMap(tenant string, tokenId string, realm string, data []byte) (map[string](interface{}), string, error) {
	scriptDataMap := make(map[string](interface{}))
	scriptedNodeMap := make(map[string](interface{}))
	err1 := json.Unmarshal([]byte(data), &scriptedNodeMap)
	if err1 != nil {
		return scriptDataMap, "", errors.New(fmt.Sprintf("ERROR: fail to unmarshal scripted node json, %s", err1.Error()))
	}
	scriptId := scriptedNodeMap["script"].(string)
	// log.Printf("script id: %s\n", scriptId)

	// get the script
	scriptData, _ := GetScriptData(tenant, tokenId, realm, scriptId)
	_ = scriptData
	// log.Printf("script data: %s\n", scriptData)

	err := json.Unmarshal([]byte(scriptData), &scriptDataMap)
	// log.Printf("journeyMap: %q\n", journeyMap)
	if err != nil {
		return scriptDataMap, "", errors.New(fmt.Sprintf("ERROR: fail to unmarshal script data json, %s", err.Error()))
	}
	delete(scriptDataMap, "_rev")
	return scriptDataMap, scriptId, nil
}

func GetEmailTemplateData(tenant string, bearerToken string, id string) ([]byte, error) {
	var b []byte

	client := resty.New()
	// client.SetDebug(true)
	jURL := fmt.Sprintf(emailTemplateURLTemplate, GetTenantURL(tenant), id)
	// log.Printf("url: %s\n", jURL)
	resp1, err1 := client.R().
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", bearerToken)).
		Get(jURL)
	// log.Printf("resp1: %s\n", resp1)
	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return b, errors.New(fmt.Sprintf("ERROR: get email template call returned %d, possible cause: script not found", resp1.StatusCode()))
		} else {
			// exports := []byte(`{"origin":"$ORIGIN", "innernodes":{}, "nodes":{}, "scripts":{}, "emailTemplates":{}}`)
			jsonMap := make(map[string](interface{}))
			err := json.Unmarshal([]byte(resp1.Body()), &jsonMap)
			if err != nil {
				return b, errors.New(fmt.Sprintf("ERROR: fail to unmarshal json, %s", err.Error()))
			}
			return resp1.Body(), nil
		}
	} else {
		return b, errors.New(fmt.Sprintf("ERROR: error getting email template, %s\n", err1.Error()))
	}
}

func GetEmailTemplateDataAsMap(tenant string, bearerToken string, data []byte) (map[string](interface{}), string, error) {
	emailTemplateDataMap := make(map[string](interface{}))
	emailTemplateNodeMap := make(map[string](interface{}))
	err1 := json.Unmarshal([]byte(data), &emailTemplateNodeMap)
	if err1 != nil {
		return emailTemplateDataMap, "", errors.New(fmt.Sprintf("ERROR: fail to unmarshal email template node json, %s", err1.Error()))
	}
	templateId := emailTemplateNodeMap["emailTemplateName"].(string)
	// log.Printf("template id: %s\n", templateId)
	templateData, _ := GetEmailTemplateData(tenant, bearerToken, templateId)
	// log.Printf("template data: %s\n", templateData)
	err := json.Unmarshal([]byte(templateData), &emailTemplateDataMap)
	// log.Printf("journeyMap: %q\n", journeyMap)
	if err != nil {
		return emailTemplateDataMap, "", errors.New(fmt.Sprintf("ERROR: fail to unmarshal email template data json, %s", err.Error()))
	}
	delete(emailTemplateDataMap, "_rev")
	return emailTemplateDataMap, templateId, nil
}

func GetOrigin(tenant string, realm string) string {
	data := []byte(fmt.Sprintf("%s%s", tenant, realm))
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func GetJourneyData(tenant string, tokenId string, bearerToken string, realm string, journey string, deploymentType string) (map[string]interface{}, error) {
	// var b []byte
	var journeyMap = make(map[string](interface{}))
	var treeMap = make(map[string](interface{}))
	var nodesMap = make(map[string](interface{}))
	var scriptsMap = make(map[string](interface{}))
	var emailTemplatesMap = make(map[string](interface{}))

	journeyMap["origin"] = GetOrigin(tenant, realm)

	// read tree object
	treeData, err1 := GetTreeData(tenant, tokenId, realm, journey)
	if err1 == nil {
		// exports := []byte(`{"origin":"$ORIGIN", "innernodes":{}, "nodes":{}, "scripts":{}, "emailTemplates":{}}`)

		err := json.Unmarshal([]byte(treeData), &treeMap)
		if err != nil {
			return journeyMap, errors.New(fmt.Sprintf("ERROR: fail to unmarshal tree json, %s", err.Error()))
		}
		delete(treeMap, "_rev")
		journeyMap["tree"] = treeMap

		// iterate over every node in tree
		nodeList := treeMap["nodes"].(map[string]interface{})
		for nodeId := range nodeList {
			nodeInfo := nodeList[nodeId].(map[string]interface{})
			// log.Printf("key: %s, type: %s\n", nodeId, nodeInfo["nodeType"])

			// get data for node
			nodeData, _ := GetNodeData(tenant, tokenId, realm, nodeId, nodeInfo["nodeType"].(string))
			nodeMap := make(map[string](interface{}))
			err := json.Unmarshal([]byte(nodeData), &nodeMap)
			// log.Printf("journeyMap: %q\n", journeyMap)
			if err != nil {
				return journeyMap, errors.New(fmt.Sprintf("ERROR: fail to unmarshal nodes json, %s", err.Error()))
			}
			delete(nodeMap, "_rev")
			nodesMap[nodeId] = nodeMap

			// if node is scripted node, get the script too
			_, scriptedType := scriptedNodes[nodeInfo["nodeType"].(string)]
			if scriptedType {
				out, id, _ := GetScriptDataAsMap(tenant, tokenId, realm, nodeData)
				scriptsMap[id] = out
			}

			// if the node is email template, get the template
			if deploymentType == "Cloud" || deploymentType == "ForgeOps" {
				_, emailTemplateType := emailTemplateNodes[nodeInfo["nodeType"].(string)]
				if emailTemplateType {
					out, id, _ := GetEmailTemplateDataAsMap(tenant, bearerToken, nodeData)
					emailTemplatesMap[id] = out
				}
			}

			// handle container nodes (page nodes only)
			_, containerNodeType := containerNodes[nodeInfo["nodeType"].(string)]
			if containerNodeType {
				// log.Printf("%s is page node\n", nodeId)
				// log.Printf("nodeData: %s\n", nodeData)
				pageNodeMap := make(map[string](interface{}))
				err2 := json.Unmarshal([]byte(nodeData), &pageNodeMap)
				if err2 != nil {
					return journeyMap, errors.New(fmt.Sprintf("ERROR: fail to unmarshal page node json, %s", err.Error()))
				}

				inPageNodesMap := make(map[string](interface{}))
				nodesInPage := pageNodeMap["nodes"].([]interface{})
				for index, _ := range nodesInPage {
					nodesInPageMap := nodesInPage[index].(map[string]interface{})
					nodeIdInPage := nodesInPageMap["_id"].(string)
					nodeTypeInPage := nodesInPageMap["nodeType"].(string)
					inPageNodeData, _ := GetNodeData(tenant, tokenId, realm, nodeIdInPage, nodeTypeInPage)
					// log.Printf("inPageNodeData: %s\n", inPageNodeData)

					inPageNodeMap := make(map[string](interface{}))
					err := json.Unmarshal([]byte(inPageNodeData), &inPageNodeMap)
					// log.Printf("journeyMap: %q\n", journeyMap)
					if err != nil {
						return journeyMap, errors.New(fmt.Sprintf("ERROR: fail to unmarshal page node data json, %s", err.Error()))
					}
					delete(inPageNodeMap, "_rev")
					inPageNodesMap[nodeIdInPage] = inPageNodeMap

					// handle scripted nodes in page node
					_, scriptedPageNdeType := scriptedNodes[nodeTypeInPage]
					if scriptedPageNdeType {
						out, id, _ := GetScriptDataAsMap(tenant, tokenId, realm, inPageNodeData)
						scriptsMap[id] = out
					}

					if deploymentType == "Cloud" || deploymentType == "ForgeOps" {
						_, emailTemplatePageNodeType := emailTemplateNodes[nodeTypeInPage]
						if emailTemplatePageNodeType {
							out, id, _ := GetEmailTemplateDataAsMap(tenant, bearerToken, inPageNodeData)
							emailTemplatesMap[id] = out

						}
					}
				}
				journeyMap["innernodes"] = inPageNodesMap
			}
		}
		journeyMap["scripts"] = scriptsMap
		journeyMap["emailTemplates"] = emailTemplatesMap
		journeyMap["nodes"] = nodesMap
		// log.Printf("journeyMap: %q\n", journeyMap)

		// callbacks[index].(map[string]interface{})
		return journeyMap, nil
	} else {
		return journeyMap, errors.New(fmt.Sprintf("ERROR: error exporting journey, %s\n", err1.Error()))
	}
}

func IsCustom(tenant string, tokenId string, realm string, versionString string, treeMap map[string](interface{})) bool {
	nodeList := treeMap["nodes"].(map[string]interface{})
	var ootbNodeTypes map[string]bool
	// log.Println(versionString)
	switch versionString {
		case "7.1.0":
			ootbNodeTypes = ootbnodetypes_7_1
		case "7.0.0", "7.0.1", "7.0.2":
			ootbNodeTypes = ootbnodetypes_7
		case "6.5.3","6.5.2.3","6.5.2.2","6.5.2.1","6.5.2","6.5.1","6.5.0.2","6.5.0.1":
			ootbNodeTypes = ootbnodetypes_6_5
		case "6.0.0.7","6.0.0.6","6.0.0.5","6.0.0.4","6.0.0.3","6.0.0.2","6.0.0.1","6.0.0":
			ootbNodeTypes = ootbnodetypes_6
		default:
			return true
	}

	// log.Printf("ootbNodeTypes: %q\n", ootbNodeTypes)
	for nodeId := range nodeList {
		nodeInfo := nodeList[nodeId].(map[string]interface{})
		// log.Printf("nodeInfo: %s and %b\n", nodeInfo, ootbNodeTypes[nodeInfo["nodeType"].(string)])
		_, ootbnode := ootbNodeTypes[nodeInfo["nodeType"].(string)]
		if !ootbnode {
			return true
		}
		_, containerNodeType := containerNodes[nodeInfo["nodeType"].(string)]
		if containerNodeType {
			nodeData, _ := GetNodeData(tenant, tokenId, realm, nodeId, nodeInfo["nodeType"].(string))
			pageNodeMap := make(map[string](interface{}))
			err := json.Unmarshal([]byte(nodeData), &pageNodeMap)
			if err != nil {
				return true
			}
			nodesInPage := pageNodeMap["nodes"].([]interface{})
			for index, _ := range nodesInPage {
				nodesInPageMap := nodesInPage[index].(map[string]interface{})
				// nodeIdInPage := nodesInPageMap["_id"].(string)
				_, ootbnode := ootbNodeTypes[nodesInPageMap["nodeType"].(string)]
				if !ootbnode {
					return true
				}
			}
		}
	}
	return false
}

func ListJourneys(tenant string, tokenId string, realm string, versionString string) (map[string]bool, error) {

	cookieName, _ := GetCookieName(tenant)
	// log.Printf("Cookie name: %s\n", cookieName)
	client := resty.New()
	// client.SetDebug(true)
	jURL := fmt.Sprintf(queryAllTreesURLTemplate, tenant, GetRealmUrl(realm))
	// log.Printf("url: %s\n", jURL)
	resp1, err1 := client.R().
		SetHeader("Accept-API-Version", amApiVersion).
		SetHeader("X-Requested-With", "XmlHttpRequest").
		SetCookie(&http.Cookie{Name: cookieName, Value: tokenId,}).
		Get(jURL)

	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return nil, errors.New(fmt.Sprintf("ERROR: list journeys call returned %d, possible cause: invalid credentials", resp1.StatusCode()))
		} else {
			jsonMap := make(map[string](interface{}))
			err := json.Unmarshal([]byte(resp1.Body()), &jsonMap)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("ERROR: fail to unmarshal json, %s", err.Error()))
			}
			results, _ := jsonMap["result"].([]interface{})
			list := make(map[string]bool)
			for index, _ := range results {
				resultMap := results[index].(map[string]interface{})
				customTree := false
				if IsCustom(tenant, tokenId, realm, versionString, resultMap) {
					customTree = true
				}
				list[resultMap["_id"].(string)] = customTree
			}
			return list, nil
		}
	} else {
		return nil, errors.New(fmt.Sprintf("ERROR: error getting journey list, %s\n", err1.Error()))
	}
}

// func GetNodeType(treeDataMap map[string]interface{}) {

// }

func DescribeTree(journeyMap map[string]interface{}) map[string]interface{} {
	treeMap := make(map[string]interface{})
	nodeTypeMap := make(map[string]int)
	scriptMap := make(map[string]string)
	treeName := journeyMap["tree"].(map[string]interface{})["_id"]
	// log.Printf("treename = %s\n", treeName)
	for nodeId := range journeyMap["nodes"].(map[string]interface{}) {
		// log.Printf("nodeId = %s\n", nodeId)
		nodeType := journeyMap["nodes"].(map[string]interface{})[nodeId].(map[string]interface{})["_type"].(map[string]interface{})["_id"]
		_, exists := nodeTypeMap[nodeType.(string)]
		if exists {
			nodeTypeMap[nodeType.(string)] += 1
		} else {
			nodeTypeMap[nodeType.(string)] = 1
		}
		// log.Printf("nodeType = %s\n", nodeType)
	}
	for nodeId := range journeyMap["innernodes"].(map[string]interface{}) {
		// log.Printf("nodeId = %s\n", nodeId)
		nodeType := journeyMap["innernodes"].(map[string]interface{})[nodeId].(map[string]interface{})["_type"].(map[string]interface{})["_id"]
		_, exists := nodeTypeMap[nodeType.(string)]
		if exists {
			nodeTypeMap[nodeType.(string)] += 1
		} else {
			nodeTypeMap[nodeType.(string)] = 1
		}
		// log.Printf("nodeType = %s\n", nodeType)
	}

	// log.Printf("nodeTypeMap: %q\n", nodeTypeMap)

	for scriptId := range journeyMap["scripts"].(map[string]interface{}) {
		description := journeyMap["scripts"].(map[string]interface{})[scriptId].(map[string]interface{})["description"]
		if description == nil {
			description = ""
		}
		scriptMap[journeyMap["scripts"].(map[string]interface{})[scriptId].(map[string]interface{})["name"].(string)] =
			description.(string)
	}
	// log.Printf("scriptMap: %q\n", scriptMap)
	treeMap["treeName"] = treeName
	treeMap["nodeTypes"] = nodeTypeMap
	treeMap["scripts"] = scriptMap
	return treeMap
}