package api_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// We only need rule_id back from the PUT response to set Terraform state.
// Orca's response fields like "tags" can vary in type (sometimes [] / sometimes {}),
// so avoid unmarshalling the whole "data" object.
type scanConfigurationRulePutResponse struct {
	Status string `json:"status"`
	Data   struct {
		RuleID string `json:"rule_id"`
	} `json:"data"`
}

type ScanConfigurationRule struct {
	RuleID           string   `json:"rule_id,omitempty"`
	AssignedPolicies []string `json:"assigned_policies,omitempty"`
	Policies         []string `json:"policies,omitempty"`
	RulePriority     int      `json:"rule_priority"`
	RuleName         string   `json:"rule_name"`
	RuleCreator      string   `json:"rule_creator,omitempty"`
	LastModified     string   `json:"last_modified,omitempty"`

	// Tags can be inconsistent in Orca responses ({} vs []), and we only need to *send* tags.
	// We send it as raw JSON (typically "[]") to keep the request correct without relying on response typing.
	Tags json.RawMessage `json:"tags,omitempty"`

	AdvancedSettings      map[string]interface{} `json:"advanced_settings,omitempty"`
	SelectorCloudAccounts []string               `json:"selector_cloud_accounts,omitempty"`
	SelectorBusinessUnits []string               `json:"selector_business_units,omitempty"`
	Feature               string                 `json:"feature"`
	Action                string                 `json:"action"`
	IsEnabledRule         bool                   `json:"is_enabled_rule"`
	IsDefaultRule         bool                   `json:"is_default_rule"`
	IsOverridePackage     bool                   `json:"is_override_package,omitempty"`
	ModifiedBy            string                 `json:"modified_by,omitempty"`
	Organization          string                 `json:"organization,omitempty"`
}

// PUT /api/scan_configuration/rules
func (c *APIClient) PutScanConfigurationRule(rule ScanConfigurationRule) (*ScanConfigurationRule, error) {
	url := fmt.Sprintf("%s/api/scan_configuration/rules", c.APIEndpoint)

	payloadBytes, err := json.Marshal(rule)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(*req)
	if err != nil {
		return nil, err
	}

	var parsed scanConfigurationRulePutResponse
	if err := resp.ReadJSON(&parsed); err != nil {
		return nil, err
	}

	if parsed.Data.RuleID == "" {
		return nil, fmt.Errorf("no rule_id returned from Orca")
	}

	// Return minimal object with ID set (Terraform only needs this).
	return &ScanConfigurationRule{RuleID: parsed.Data.RuleID}, nil
}
