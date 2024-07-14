package zabbix

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/claranet/go-zabbix-api"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// HostInterfaceTypes zabbix different interface type
var HostInterfaceTypes = map[string]zabbix.InterfaceType{
	"agent": 1,
	"snmp":  2,
	"ipmi":  3,
	"jmx":   4,
}

var HostInterfaceTypeStrings = map[zabbix.InterfaceType]string{
	zabbix.Agent: "agent",
	zabbix.SNMP:  "snmp",
	zabbix.IPMI:  "ipmi",
	zabbix.JMX:   "jmx",
}

var interfaceSchema *schema.Resource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"dns": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},
		"ip": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
		},
		"main": &schema.Schema{
			Type:     schema.TypeBool,
			Required: true,
		},
		"port": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "10050",
		},
		"type": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			Default:  "agent",
		},
		"interface_id": &schema.Schema{
			Type:     schema.TypeString,
			Computed: true,
		},
		"details": {
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"version": &schema.Schema{
						Type:     schema.TypeInt,
						Optional: true,
						Default:  2,
					},
					"bulk": &schema.Schema{
						Type:     schema.TypeInt,
						Optional: true,
						Default:  1,
					},
					"community": &schema.Schema{
						Type:     schema.TypeString,
						Optional: true,
					},
					"max_repetitions": &schema.Schema{
						Type:     schema.TypeInt,
						Optional: true,
						Default:  10,
					},
					"securityname": &schema.Schema{
						Type:     schema.TypeString,
						Optional: true,
					},
					"securitylevel": &schema.Schema{
						Type:     schema.TypeInt,
						Optional: true,
						Default:  0,
					},
					"authpassphrase": &schema.Schema{
						Type:     schema.TypeString,
						Optional: true,
					},
					"privpassphrase": &schema.Schema{
						Type:     schema.TypeString,
						Optional: true,
					},
					"authprotocol": &schema.Schema{
						Type:     schema.TypeInt,
						Optional: true,
						Default:  0,
					},
					"privprotocol": &schema.Schema{
						Type:     schema.TypeInt,
						Optional: true,
						Default:  0,
					},
					"contextname": &schema.Schema{
						Type:     schema.TypeString,
						Optional: true,
					},
				},
			},
		},
	},
}

func resourceZabbixHost() *schema.Resource {
	return &schema.Resource{
		Create: resourceZabbixHostCreate,
		Read:   resourceZabbixHostRead,
		Update: resourceZabbixHostUpdate,
		Delete: resourceZabbixHostDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"host": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "Technical name of the host.",
			},
			"host_id": &schema.Schema{
				Type:        schema.TypeString,
				Computed:    true,
				Description: "(readonly) ID of the host",
			},
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Computed:    true,
				Description: "Visible name of the host.",
			},
			"monitored": &schema.Schema{
				Type:     schema.TypeBool,
				Default:  true,
				Optional: true,
			},
			"interfaces": &schema.Schema{
				Type:     schema.TypeList,
				Elem:     interfaceSchema,
				Optional: true,
			},
			"groups": &schema.Schema{
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Required: true,
			},
			"templates": &schema.Schema{
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"macro": &schema.Schema{
				Type:        schema.TypeMap,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "User macros for the host.",
			},
		},
	}
}

func getInterfaces(d *schema.ResourceData) (zabbix.HostInterfaces, error) {
	if d.Get("interfaces") == nil {
		return nil, nil
	}
	interfaceCount := d.Get("interfaces.#").(int)
	interfaces := make(zabbix.HostInterfaces, interfaceCount)

	for i := 0; i < interfaceCount; i++ {
		prefix := fmt.Sprintf("interfaces.%d.", i)

		interfaceType := d.Get(prefix + "type").(string)

		typeID, ok := HostInterfaceTypes[interfaceType]
		if !ok {
			return nil, fmt.Errorf("%s isn't a valid interface type", interfaceType)
		}

		interfaceId := d.Get(prefix + "interface_id").(string)
		ip := d.Get(prefix + "ip").(string)
		dns := d.Get(prefix + "dns").(string)

		if ip == "" && dns == "" {
			return nil, errors.New("At least one of dns or ip must be set")
		}

		useip := 1
		if ip == "" {
			useip = 0
		}

		main := 1
		if !d.Get(prefix + "main").(bool) {
			main = 0
		}

		detailsList := d.Get(prefix + "details").([]interface{})
		details := zabbix.InterfaceDetails{}

		if len(detailsList) > 0 {
			detailMap := detailsList[0].(map[string]interface{})
			if version, ok := detailMap["version"].(int); ok {
				details.Version = version
			}
			if community, ok := detailMap["community"].(string); ok {
				details.Community = community
			}
			if bulk, ok := detailMap["bulk"].(int); ok {
				details.Bulk = bulk
			}
			if maxRepetitions, ok := detailMap["max_repetitions"].(int); ok {
				details.MaxRepetitions = maxRepetitions
			}
			if securityName, ok := detailMap["securityname"].(string); ok {
				details.SecurityName = securityName
			}
			if securityLevel, ok := detailMap["securitylevel"].(int); ok {
				details.SecurityLevel = securityLevel
			}
			if authPassphrase, ok := detailMap["authpassphrase"].(string); ok {
				details.AuthPassphrase = authPassphrase
			}
			if privPassphrase, ok := detailMap["privpassphrase"].(string); ok {
				details.PrivPassphrase = privPassphrase
			}
			if authProtocol, ok := detailMap["authprotocol"].(int); ok {
				details.AuthProtocol = authProtocol
			}
			if privProtocol, ok := detailMap["privprotocol"].(int); ok {
				details.PrivProtocol = privProtocol
			}
			if contextName, ok := detailMap["contextname"].(string); ok {
				details.ContextName = contextName
			}
		}

		interfaces[i] = zabbix.HostInterface{
			InterfaceID: interfaceId,
			DNS:         dns,
			IP:          ip,
			Main:        main,
			Port:        d.Get(prefix + "port").(string),
			Type:        typeID,
			UseIP:       useip,
			Details:     details,
		}
	}

	return interfaces, nil
}

func getHostGroups(d *schema.ResourceData, api *zabbix.API) (zabbix.HostGroupIDs, error) {
	configGroups := d.Get("groups").(*schema.Set)
	setHostGroups := make([]string, configGroups.Len())

	for i, g := range configGroups.List() {
		setHostGroups[i] = g.(string)
	}

	log.Printf("[DEBUG] Groups %v\n", setHostGroups)

	groupParams := zabbix.Params{
		"output": "extend",
		"filter": map[string]interface{}{
			"name": setHostGroups,
		},
	}

	groups, err := api.HostGroupsGet(groupParams)

	if err != nil {
		return nil, err
	}

	if len(groups) < configGroups.Len() {
		log.Printf("[DEBUG] Not all of the specified groups were found on zabbix server")

		for _, n := range configGroups.List() {
			found := false

			for _, g := range groups {
				if n == g.Name {
					found = true
					break
				}
			}

			if !found {
				return nil, fmt.Errorf("Host group %s doesnt exist in zabbix server", n)
			}
			log.Printf("[DEBUG] %s exists on zabbix server", n)
		}
	}

	hostGroups := make(zabbix.HostGroupIDs, len(groups))

	for i, g := range groups {
		hostGroups[i] = zabbix.HostGroupID{
			GroupID: g.GroupID,
		}
	}

	return hostGroups, nil
}

func getTemplates(d *schema.ResourceData, api *zabbix.API) (zabbix.TemplateIDs, error) {
	configTemplates := d.Get("templates").(*schema.Set)
	templateNames := make([]string, configTemplates.Len())

	if configTemplates.Len() == 0 {
		return nil, nil
	}

	for i, g := range configTemplates.List() {
		templateNames[i] = g.(string)
	}

	log.Printf("[DEBUG] Templates %v\n", templateNames)

	groupParams := zabbix.Params{
		"output": "extend",
		"filter": map[string]interface{}{
			"host": templateNames,
		},
	}

	templates, err := api.TemplatesGet(groupParams)

	if err != nil {
		return nil, err
	}

	if len(templates) < configTemplates.Len() {
		log.Printf("[DEBUG] Not all of the specified templates were found on zabbix server")

		for _, n := range configTemplates.List() {
			found := false

			for _, g := range templates {
				if n == g.Name {
					found = true
					break
				}
			}

			if !found {
				return nil, fmt.Errorf("Template %s doesnt exist in zabbix server", n)
			}
			log.Printf("[DEBUG] Template %s exists on zabbix server", n)
		}
	}

	hostTemplates := make(zabbix.TemplateIDs, len(templates))

	for i, t := range templates {
		hostTemplates[i] = zabbix.TemplateID{
			TemplateID: t.TemplateID,
		}
	}

	return hostTemplates, nil
}

func getHostMacro(d *schema.ResourceData) zabbix.Macros {
	var macros zabbix.Macros

	terraformMacros := d.Get("macro").(map[string]interface{})
	for i, terraformMacro := range terraformMacros {
		macro := zabbix.Macro{
			MacroName: fmt.Sprintf("{$%s}", i),
			Value:     terraformMacro.(string),
		}
		macros = append(macros, macro)
	}
	return macros
}

func createHostObj(d *schema.ResourceData, api *zabbix.API) (*zabbix.Host, error) {
	host := zabbix.Host{
		Host:   d.Get("host").(string),
		Name:   d.Get("name").(string),
		Status: 0,
	}

	//0 is monitored, 1 - unmonitored host
	if !d.Get("monitored").(bool) {
		host.Status = 1
	}

	hostGroups, err := getHostGroups(d, api)

	if err != nil {
		return nil, err
	}

	host.GroupIds = hostGroups

	interfaces, err := getInterfaces(d)

	if err != nil {
		return nil, err
	}

	host.Interfaces = interfaces

	templates, err := getTemplates(d, api)

	if err != nil {
		return nil, err
	}

	host.TemplateIDs = templates

	host.UserMacros = getHostMacro(d)

	// Ensure macros is not null
	if host.UserMacros == nil {
		host.UserMacros = zabbix.Macros{}
	}

	return &host, nil
}

func resourceZabbixHostCreate(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	host, err := createHostObj(d, api)

	if err != nil {
		return err
	}

	hosts := zabbix.Hosts{*host}

	err = api.HostsCreate(hosts)

	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Created host id is %s", hosts[0].HostID)

	d.SetId(hosts[0].HostID)

	return resourceZabbixHostRead(d, meta)
}

func resourceZabbixHostRead(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	log.Printf("[DEBUG] Will read host with id %s", d.Id())

	hosts, err := api.HostsGet(zabbix.Params{
		"hostids":               d.Id(),
		"selectInterfaces":      "extend",
		"selectParentTemplates": []string{"name"},
		"selectMacros":          "extend",
	})

	if err != nil {
		return err
	}

	if len(hosts) != 1 {
		return fmt.Errorf("Expected one host with id %s and got %d hosts", d.Id(), len(hosts))
	}
	host := hosts[0]
	log.Printf("[DEBUG] Host name is %s", host.Name)

	d.Set("host", host.Host)
	d.Set("host_id", host.HostID)
	d.Set("name", host.Name)

	d.Set("monitored", host.Status == 0)

	interfaces := make([]map[string]interface{}, len(host.Interfaces))

	for i, ifa := range host.Interfaces {
		details := make([]map[string]interface{}, 0)
		if (ifa.Details != zabbix.InterfaceDetails{}) {
			details = append(details, map[string]interface{}{
				"version":         ifa.Details.Version,
				"community":       ifa.Details.Community,
				"bulk":            ifa.Details.Bulk,
				"max_repetitions": ifa.Details.MaxRepetitions,
				"securityname":    ifa.Details.SecurityName,
				"securitylevel":   ifa.Details.SecurityLevel,
				"authpassphrase":  ifa.Details.AuthPassphrase,
				"privpassphrase":  ifa.Details.PrivPassphrase,
				"authprotocol":    ifa.Details.AuthProtocol,
				"privprotocol":    ifa.Details.PrivProtocol,
				"contextname":     ifa.Details.ContextName,
			})
		}

		interfaces[i] = map[string]interface{}{
			"interface_id": ifa.InterfaceID,
			"dns":          ifa.DNS,
			"ip":           ifa.IP,
			"main":         ifa.Main == 1,
			"port":         ifa.Port,
			"type":         HostInterfaceTypeStrings[ifa.Type],
			"details":      details,
		}
	}

	d.Set("interfaces", interfaces)

	templateNames := make([]string, len(host.Templates))

	for i, t := range host.Templates {
		templateNames[i] = t.Name
	}

	d.Set("templates", templateNames)

	macros := make(map[string]interface{}, len(host.UserMacros))

	for _, macro := range host.UserMacros {
		var name string
		if noPrefix := strings.Split(macro.MacroName, "{$"); len(noPrefix) == 2 {
			name = noPrefix[1]
		} else {
			return fmt.Errorf("Invalid macro name \"%s\"", macro.MacroName)
		}
		if noSuffix := strings.Split(name, "}"); len(noSuffix) == 2 {
			name = noSuffix[0]
		} else {
			return fmt.Errorf("Invalid macro name \"%s\"", macro.MacroName)
		}
		macros[name] = macro.Value
	}

	d.Set("macro", macros)

	params := zabbix.Params{
		"output": []string{"name"},
		"hostids": []string{
			d.Id(),
		},
	}

	groups, err := api.HostGroupsGet(params)

	if err != nil {
		return err
	}

	groupNames := make([]string, len(groups))

	for i, g := range groups {
		groupNames[i] = g.Name
	}

	d.Set("groups", groupNames)

	return nil
}

func resourceZabbixHostUpdate(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	host, err := createHostObj(d, api)

	if err != nil {
		return err
	}

	host.HostID = d.Id()

	hosts := zabbix.Hosts{*host}

	err = api.HostsUpdate(hosts)

	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Created host id is %s", hosts[0].HostID)

	return resourceZabbixHostRead(d, meta)
}

func resourceZabbixHostDelete(d *schema.ResourceData, meta interface{}) error {
	api := meta.(*zabbix.API)

	return api.HostsDeleteByIds([]string{d.Id()})
}
