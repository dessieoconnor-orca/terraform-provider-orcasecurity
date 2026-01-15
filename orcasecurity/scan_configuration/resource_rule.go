package scan_configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"terraform-provider-orcasecurity/orcasecurity/api_client"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &scanConfigurationRuleResource{}
	_ resource.ResourceWithConfigure   = &scanConfigurationRuleResource{}
	_ resource.ResourceWithImportState = &scanConfigurationRuleResource{}
)

type scanConfigurationRuleResource struct {
	apiClient *api_client.APIClient
}

type scanConfigurationRuleModel struct {
	ID                    types.String   `tfsdk:"id"`
	RuleName              types.String   `tfsdk:"rule_name"`
	RulePriority          types.Int64    `tfsdk:"rule_priority"`
	IsEnabledRule         types.Bool     `tfsdk:"is_enabled_rule"`
	IsDefaultRule         types.Bool     `tfsdk:"is_default_rule"`
	Feature               types.String   `tfsdk:"feature"`
	Action                types.String   `tfsdk:"action"`
	SelectorCloudAccounts []types.String `tfsdk:"selector_cloud_accounts"`
	SelectorBusinessUnits []types.String `tfsdk:"selector_business_units"`
	Tags                  []types.String `tfsdk:"tags"`
	Policies              []types.String `tfsdk:"policies"`
	AdvancedSettingsJSON  types.String   `tfsdk:"advanced_settings_json"`
}

func NewScanConfigurationRuleResource() resource.Resource {
	return &scanConfigurationRuleResource{}
}

func (r *scanConfigurationRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scan_configuration_rule"
}

func (r *scanConfigurationRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.apiClient = req.ProviderData.(*api_client.APIClient)
}

func (r *scanConfigurationRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

func (r *scanConfigurationRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Orca Scan Configuration Rule (PUT-only until a rules GET endpoint is added).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"rule_name":               schema.StringAttribute{Required: true},
			"rule_priority":           schema.Int64Attribute{Required: true},
			"is_enabled_rule":         schema.BoolAttribute{Required: true},
			"is_default_rule":         schema.BoolAttribute{Optional: true},
			"feature":                 schema.StringAttribute{Required: true},
			"action":                  schema.StringAttribute{Required: true},
			"selector_cloud_accounts": schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"selector_business_units": schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"tags":                    schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"policies":                schema.ListAttribute{Optional: true, ElementType: types.StringType},
			"advanced_settings_json":  schema.StringAttribute{Optional: true},
		},
	}
}

func (r *scanConfigurationRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scanConfigurationRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	r.put(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *scanConfigurationRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scanConfigurationRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *scanConfigurationRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan scanConfigurationRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	r.put(ctx, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *scanConfigurationRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state scanConfigurationRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	state.IsEnabledRule = types.BoolValue(false)
	r.put(ctx, &state, &resp.Diagnostics)
	resp.State.RemoveResource(ctx)
}

func (r *scanConfigurationRuleResource) put(ctx context.Context, m *scanConfigurationRuleModel, diags *diag.Diagnostics) {
	cloudAccounts := extractStrings(m.SelectorCloudAccounts)
	businessUnits := extractStrings(m.SelectorBusinessUnits)
	tags := extractStrings(m.Tags)
	policies := extractStrings(m.Policies)

	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		diags.AddError("Error marshalling tags", err.Error())
		return
	}

	advanced := map[string]interface{}{}
	if !m.AdvancedSettingsJSON.IsNull() && m.AdvancedSettingsJSON.ValueString() != "" {
		if err := json.Unmarshal([]byte(m.AdvancedSettingsJSON.ValueString()), &advanced); err != nil {
			diags.AddError("Invalid advanced_settings_json", err.Error())
			return
		}
	}

	rule := api_client.ScanConfigurationRule{
		RuleName:              m.RuleName.ValueString(),
		RulePriority:          int(m.RulePriority.ValueInt64()),
		IsEnabledRule:         m.IsEnabledRule.ValueBool(),
		IsDefaultRule:         m.IsDefaultRule.ValueBool(),
		Feature:               m.Feature.ValueString(),
		Action:                m.Action.ValueString(),
		SelectorCloudAccounts: cloudAccounts,
		SelectorBusinessUnits: businessUnits,
		Tags:                  tagsJSON,
		Policies:              policies,
		AdvancedSettings:      advanced,
	}

	created, err := r.apiClient.PutScanConfigurationRule(rule)
	if err != nil {
		diags.AddError("Error calling Orca API", err.Error())
		return
	}

	m.ID = types.StringValue(created.RuleID)
	tflog.Info(ctx, fmt.Sprintf("Scan configuration rule upserted: %s", created.RuleID))
}

func extractStrings(input []types.String) []string {
	out := []string{}
	for _, v := range input {
		if !v.IsNull() && !v.IsUnknown() {
			out = append(out, v.ValueString())
		}
	}
	return out
}
