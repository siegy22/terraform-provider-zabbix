package zabbix

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/mcuadros/go-version"
)

func dataSourceZabbixServer() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceZabbixServerRead,
		Schema: map[string]*schema.Schema{
			"server_version": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Version of the Zabbix server.",
			},
			"compare_version": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Version to compare the Zabbix server version to.",
			},
			"server_version_gt": &schema.Schema{
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Returns true if the version of the Zabbix server is strictly greater than the version provided in `compare_version`.",
			},
			"server_version_lt": &schema.Schema{
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Returns true if the version of the Zabbix server is strictly less than the version provided in `compare_version`.",
			},
			"server_version_ge": &schema.Schema{
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Returns true if the version of the Zabbix server is greater or equal to the version provided in `compare_version`.",
			},
			"server_version_le": &schema.Schema{
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Returns true if the version of the Zabbix server is less or equal to the version provided in `compare_version`.",
			},
			"unit_time_days": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "String representation of the days unit used by the Zabbix server (`d` for version 3.4+, empty string otherwise).",
			},
			"unit_time_hours": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "String representation of the hours unit used by the Zabbix server (`h` for version 3.4+, empty string otherwise).",
			},
			"unit_time_minutes": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "String representation of the minutes unit used by the Zabbix server (`m` for version 3.4+, empty string otherwise).",
			},
			"unit_time_seconds": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "String representation of the seconds unit used by the Zabbix server (`s` for version 3.4+, empty string otherwise).",
			},
			"unit_time_weeks": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "String representation of the weeks unit used by the Zabbix server (`w` for version 3.4+, empty string otherwise).",
			},
		},
	}
}

func dataSourceZabbixServerRead(d *schema.ResourceData, meta interface{}) (err error) {
	var serverVersion string
	if v, ok := d.GetOkExists("server_version"); ok {
		serverVersion = v.(string)
		log.Printf("[DEBUG] Forcing Zabbix Server version to %s\n", serverVersion)
	} else {
		serverVersion = getZabbixServerVersion(meta)
		if serverVersion == "" {
			return fmt.Errorf("Failed to get Zabbix Server version")
		}

		log.Printf("[DEBUG] Actual Zabbix Server version is %s\n", serverVersion)
	}

	d.SetId(fmt.Sprintf("zabbix_server_%s", strings.ReplaceAll(serverVersion, ".", "_")))
	d.Set("server_version", serverVersion)

	d.Set("unit_time_days", getZabbixServerUnitDays(serverVersion))
	d.Set("unit_time_hours", getZabbixServerUnitHours(serverVersion))
	d.Set("unit_time_minutes", getZabbixServerUnitMinutes(serverVersion))
	d.Set("unit_time_seconds", getZabbixServerUnitSeconds(serverVersion))
	d.Set("unit_time_weeks", getZabbixServerUnitWeeks(serverVersion))

	if v, ok := d.GetOkExists("compare_version"); ok {
		compareVersion := v.(string)
		d.Set("server_version_gt", version.Compare(serverVersion, compareVersion, ">"))
		d.Set("server_version_lt", version.Compare(serverVersion, compareVersion, "<"))
		d.Set("server_version_ge", version.Compare(serverVersion, compareVersion, ">="))
		d.Set("server_version_le", version.Compare(serverVersion, compareVersion, "<="))
	}

	return nil
}
