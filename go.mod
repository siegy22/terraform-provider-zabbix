module github.com/claranet/terraform-provider-zabbix

go 1.16

require (
	github.com/claranet/go-zabbix-api v1.0.0
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.8.0
	github.com/mcuadros/go-version v0.0.0-20190830083331-035f6764e8d2
)

replace github.com/claranet/go-zabbix-api v1.0.0 => github.com/elastic-infra/go-zabbix-api v1.1.0
