// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &BinaryUploadConfigSettingsResource{}
var _ resource.ResourceWithConfigure = &BinaryUploadConfigSettingsResource{}
var _ resource.ResourceWithImportState = &BinaryUploadConfigSettingsResource{}
var _ resource.ResourceWithIdentity = &BinaryUploadConfigSettingsResource{}

func NewBinaryUploadConfigSettingsResource() resource.Resource {
	return &BinaryUploadConfigSettingsResource{}
}

type BinaryUploadConfigSettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type BinaryUploadConfigSettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type BinaryUploadConfigSettingsResourceModel struct {
	BucketUrl types.String `tfsdk:"bucket_url"`
}

func (r *BinaryUploadConfigSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_binary_upload_config"
}

func (r *BinaryUploadConfigSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_binary_upload_config resource manages the bucket Santa uploads binaries to when Workshop requests a binary upload. You need the read:settings and write:settings permissions. This is a singleton resource, one per tenant. Creating it sets the bucket URL and replaces any value the tenant already has. Destroying it removes it from state and leaves the tenant's setting as it was.",
		MarkdownDescription: "The `nps_workshop_settings_binary_upload_config` resource manages the bucket Santa uploads binaries to when Workshop requests a binary upload.\n\nYou need the `read:settings` and `write:settings` permissions.\n\nThis is a singleton resource, one per tenant. Creating it sets the bucket URL and replaces any value the tenant already has. Destroying it removes it from state and leaves the tenant's setting as it was.",

		Attributes: map[string]schema.Attribute{
			"bucket_url": schema.StringAttribute{
				Description:         "The bucket URL, as gs://bucket or s3://bucket. Set it to the empty string to clear the setting, which turns binary upload off.",
				MarkdownDescription: "The bucket URL, as `gs://bucket` or `s3://bucket`. Set it to the empty string to clear the setting, which turns binary upload off.",
				Required:            true,
			},
		},
	}
}

func (r *BinaryUploadConfigSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	pd, ok := req.ProviderData.(*NPSProviderResourceData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected NPSProviderResourceData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = pd.Client
}

func (r *BinaryUploadConfigSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data BinaryUploadConfigSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.setBucketURL(ctx, data.BucketUrl, &resp.Diagnostics) {
		return
	}

	tflog.Info(ctx, "Created binary upload config resource")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, BinaryUploadConfigSettingsIdentityModel{Id: types.StringValue("binary_upload_config")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BinaryUploadConfigSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	ret, err := r.client.GetBinaryUploadConfig(ctx, apipb.GetBinaryUploadConfigRequest_builder{}.Build())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to get binary upload config: %v", err))
		return
	}

	// A tenant with no bucket may report no URL at all. Store that as the
	// empty string, the value a configuration uses to clear the bucket, so
	// that such a configuration doesn't plan a change on every run.
	data := BinaryUploadConfigSettingsResourceModel{BucketUrl: types.StringValue(ret.GetBucketUrl())}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, BinaryUploadConfigSettingsIdentityModel{Id: types.StringValue("binary_upload_config")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BinaryUploadConfigSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan BinaryUploadConfigSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.setBucketURL(ctx, plan.BucketUrl, &resp.Diagnostics) {
		return
	}

	tflog.Info(ctx, "Updated binary upload config")

	resp.Diagnostics.Append(resp.Identity.Set(ctx, BinaryUploadConfigSettingsIdentityModel{Id: types.StringValue("binary_upload_config")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// setBucketURL always sends bucket_url, even when it is empty.
// UpdateBinaryUploadConfig leaves the setting alone when the field is absent
// and clears it when the field is an empty string.
func (r *BinaryUploadConfigSettingsResource) setBucketURL(ctx context.Context, bucketURL types.String, diags *diag.Diagnostics) bool {
	url := bucketURL.ValueString()
	if _, err := r.client.UpdateBinaryUploadConfig(ctx, apipb.UpdateBinaryUploadConfigRequest_builder{BucketUrl: &url}.Build()); err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to update binary upload config: %v", err))
		return false
	}
	return true
}

func (r *BinaryUploadConfigSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Singleton: removing the resource from Terraform state does not modify
	// the server-side configuration.
	tflog.Info(ctx, "Removed binary upload config from Terraform state (server-side configuration unchanged)")
}

func (r *BinaryUploadConfigSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &BinaryUploadConfigSettingsResourceModel{})...)
}

func (r *BinaryUploadConfigSettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}
