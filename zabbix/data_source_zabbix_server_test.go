package zabbix

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccZabbixDataSourceServer_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccZabbixDataSourceServerConfig_basic(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.zabbix_server.test", "server_version"),
					testCheckResourceAttrValueFunc("data.zabbix_server.test", "unit_time_days", getZabbixServerUnitDays),
					testCheckResourceAttrValueFunc("data.zabbix_server.test", "unit_time_hours", getZabbixServerUnitHours),
					testCheckResourceAttrValueFunc("data.zabbix_server.test", "unit_time_minutes", getZabbixServerUnitMinutes),
					testCheckResourceAttrValueFunc("data.zabbix_server.test", "unit_time_seconds", getZabbixServerUnitSeconds),
					testCheckResourceAttrValueFunc("data.zabbix_server.test", "unit_time_weeks", getZabbixServerUnitWeeks),
					resource.TestCheckNoResourceAttr("data.zabbix_server.test", "server_version_gt"),
					resource.TestCheckNoResourceAttr("data.zabbix_server.test", "server_version_lt"),
					resource.TestCheckNoResourceAttr("data.zabbix_server.test", "server_version_ge"),
					resource.TestCheckNoResourceAttr("data.zabbix_server.test", "server_version_le"),
				),
			},
		},
	})
}

func TestAccZabbixDataSourceServer_force_32(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccZabbixDataSourceServerConfig_force_version("3.2.0", "3.2.0"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version", "3.2.0"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_days", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_hours", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_minutes", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_seconds", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_weeks", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_gt", "false"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_lt", "false"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_ge", "true"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_le", "true"),
				),
			},
			{
				Config: testAccZabbixDataSourceServerConfig_force_version("3.2.11", "3.4.0"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version", "3.2.11"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_days", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_hours", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_minutes", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_seconds", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_weeks", ""),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_gt", "false"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_lt", "true"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_ge", "false"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_le", "true"),
				),
			},
		},
	})
}

func TestAccZabbixDataSourceServer_force_34(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccZabbixDataSourceServerConfig_force_version("3.4.0", "3.2.0"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version", "3.4.0"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_days", "d"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_hours", "h"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_minutes", "m"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_seconds", "s"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_weeks", "w"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_gt", "true"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_lt", "false"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_ge", "true"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_le", "false"),
				),
			},
			{
				Config: testAccZabbixDataSourceServerConfig_force_version("3.4.15", "3.4.0"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version", "3.4.15"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_days", "d"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_hours", "h"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_minutes", "m"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_seconds", "s"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "unit_time_weeks", "w"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_gt", "true"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_lt", "false"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_ge", "true"),
					resource.TestCheckResourceAttr("data.zabbix_server.test", "server_version_le", "false"),
				),
			},
		},
	})
}

func testCheckResourceAttrValueFunc(resourceName, key string, valueFunc func(string) string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// retrieve the resource by name from state
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("Resource ID is not set")
		}

		// retrieve the expected value depending on the zabbix server version
		zabbixVersion := getZabbixServerVersion(testAccProvider.Meta())
		value := valueFunc(zabbixVersion)
		v := rs.Primary.Attributes[key]
		if v != value {
			return fmt.Errorf(
				"%s: Attribute '%s' expected %#v, got %#v",
				resourceName,
				key,
				value,
				v,
			)
		}

		return nil
	}
}

func testAccZabbixDataSourceServerConfig_basic() string {
	return `
data "zabbix_server" "test" {
}
`
}

func testAccZabbixDataSourceServerConfig_force_version(serverVersion, versionCompare string) string {
	return fmt.Sprintf(`
data "zabbix_server" "test" {
	server_version  = "%s"
	compare_version = "%s"
}
`, serverVersion, versionCompare)
}
