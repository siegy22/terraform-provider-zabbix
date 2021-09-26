package zabbix

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var testAccProviders map[string]terraform.ResourceProvider
var testAccProvider *schema.Provider

func TestProvider(t *testing.T) {
	if err := Provider().(*schema.Provider).InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ terraform.ResourceProvider = Provider()
}

func init() {
	testAccProvider = Provider().(*schema.Provider)
	testAccProviders = map[string]terraform.ResourceProvider{
		"zabbix": testAccProvider,
	}
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("ZABBIX_SERVER_URL"); v == "" {
		t.Fatal("ZABBIX_SERVER_URL must be set for acceptance tests")
	}
	if v := os.Getenv("ZABBIX_USER"); v == "" {
		t.Fatal("ZABBIX_USER must be set for acceptance tests")
	}
	if v := os.Getenv("ZABBIX_PASSWORD"); v == "" {
		t.Fatal("ZABBIX_PASSWORD must be set for acceptance tests")
	}

	err := testAccProvider.Configure(terraform.NewResourceConfigRaw(nil))
	if err != nil {
		t.Fatal(err)
	}
}
