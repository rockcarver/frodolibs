package frodolibs

import (
    "fmt"
	"errors"
	"github.com/go-resty/resty/v2"
)

const idmConfigEntityURLTemplate string = "%s/openidm/config/%s"

func ExportConfigEntity(frt FRToken, entityName string) ([]byte, error) {
	var b []byte
	client := resty.New()
	// client.SetDebug(true)
	resp1, err1 := client.R().
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", frt.bearerToken)).
		Get(fmt.Sprintf(idmConfigEntityURLTemplate, GetTenantURL(frt.tenant), entityName))
	if err1 == nil {
		if resp1.StatusCode() < 200 || resp1.StatusCode() > 399 {
			return b, errors.New(fmt.Sprintf("ERROR: export entity call returned %d", resp1.StatusCode()))
		} else {
			return resp1.Body(), nil
		}
	} else {
		return b, errors.New(fmt.Sprintf("ERROR: error exporting entity, %s\n", err1.Error()))
	}
}