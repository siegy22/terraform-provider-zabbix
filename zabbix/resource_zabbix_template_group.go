package zabbix

import (
	"log"
	"strings"

	"github.com/claranet/go-zabbix-api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceZabbixTemplateGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceZabbixTemplateGroupCreate,
		Read:   resourceZabbixTemplateGroupRead,
		Exists: resourceZabbixTemplateGroupExists,
		Update: resourceZabbixTemplateGroupUpdate,
		Delete: resourceZabbixTemplateGroupDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the template group.",
			},
			"group_id": &schema.Schema{
				Type:     schema.TypeString,
				Required: false,
				Computed: true,
			},
		},
	}
}

func resourceZabbixTemplateGroupCreate(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	templateGroup := zabbix.TemplateGroup{
		Name: d.Get("name").(string),
	}
	groups := zabbix.TemplateGroups{templateGroup}

	err := api.TemplateGroupsCreate(groups)
	if err != nil {
		return err
	}

	groupID := groups[0].GroupID

	log.Printf("[DEBUG] Created template group, id is %s", groupID)

	d.Set("group_id", groupID)
	d.SetId(groupID)

	return nil
}

func resourceZabbixTemplateGroupRead(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	log.Printf("[DEBUG] Will read template group with id %s", d.Id())

	group, err := api.TemplateGroupGetByID(d.Id())

	if err != nil {
		return err
	}

	d.Set("name", group.Name)
	d.Set("group_id", group.GroupID)

	return nil
}

func resourceZabbixTemplateGroupExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	api := meta.(*zabbix.API)

	_, err := api.TemplateGroupGetByID(d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "Expected exactly one result") {
			log.Printf("[DEBUG] Template group with id %s doesn't exist", d.Id())
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func resourceZabbixTemplateGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	templateGroup := zabbix.TemplateGroup{
		Name:    d.Get("name").(string),
		GroupID: d.Id(),
	}

	return api.TemplateGroupsUpdate(zabbix.TemplateGroups{templateGroup})
}

func resourceZabbixTemplateGroupDelete(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	return api.TemplateGroupsDeleteByIds([]string{d.Id()})
}
