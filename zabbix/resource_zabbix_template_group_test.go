package zabbix

import (
	"fmt"
	"testing"

	"github.com/claranet/go-zabbix-api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccZabbixTemplateGroup_Basic(t *testing.T) {
	groupName := fmt.Sprintf("template_groud_%s", acctest.RandString(5))
	var templateGroup zabbix.TemplateGroup
	expectedTemplateGroup := zabbix.TemplateGroup{Name: groupName}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckZabbixTemplateGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccZabbixTemplateGroupConfig(groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckZabbixTemplateGroupExists("zabbix_template_group.zabbix", &templateGroup),
					testAccCheckZabbixTemplateGroupAttributes(&templateGroup, expectedTemplateGroup),
					resource.TestCheckResourceAttr("zabbix_template_group.zabbix", "name", groupName),
				),
			},
		},
	})
}

func testAccCheckZabbixTemplateGroupDestroy(s *terraform.State) error {
	api := testAccProvider.Meta().(*zabbix.API)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "zabbix_template_group" {
			continue
		}

		_, err := api.TemplateGroupGetByID(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("Template group still exists")
		}
		expectedError := "Expected exactly one result, got 0."
		if err.Error() != expectedError {
			return fmt.Errorf("expected error : %s, got : %s", expectedError, err.Error())
		}
	}
	return nil
}

func testAccZabbixTemplateGroupConfig(groupName string) string {
	return fmt.Sprintf(`
		resource "zabbix_template_group" "zabbix" {
			name = "%s"
		}`, groupName,
	)
}

func testAccCheckZabbixTemplateGroupExists(resource string, templateGroup *zabbix.TemplateGroup) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		rs, ok := state.RootModule().Resources[resource]
		if !ok {
			return fmt.Errorf("Not found; %s", resource)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No record ID set")
		}

		api := testAccProvider.Meta().(*zabbix.API)
		group, err := api.TemplateGroupGetByID(rs.Primary.ID)
		if err != nil {
			return err
		}
		*templateGroup = *group
		return nil
	}
}

func testAccCheckZabbixTemplateGroupAttributes(templateGroup *zabbix.TemplateGroup, want zabbix.TemplateGroup) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		if templateGroup.Name != want.Name {
			return fmt.Errorf("got template name : %q, expected : %q", templateGroup.Name, want.Name)
		}
		return nil
	}
}
