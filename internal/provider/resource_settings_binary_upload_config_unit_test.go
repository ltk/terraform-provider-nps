// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

type fakeBinaryUploadConfigClient struct {
	svcpb.WorkshopServiceClient

	stored  *string
	updates []*apipb.UpdateBinaryUploadConfigRequest
}

func (f *fakeBinaryUploadConfigClient) GetBinaryUploadConfig(ctx context.Context, in *apipb.GetBinaryUploadConfigRequest, _ ...grpc.CallOption) (*apipb.GetBinaryUploadConfigResponse, error) {
	return apipb.GetBinaryUploadConfigResponse_builder{BucketUrl: f.stored}.Build(), nil
}

func (f *fakeBinaryUploadConfigClient) UpdateBinaryUploadConfig(ctx context.Context, in *apipb.UpdateBinaryUploadConfigRequest, _ ...grpc.CallOption) (*apipb.UpdateBinaryUploadConfigResponse, error) {
	f.updates = append(f.updates, in)
	return apipb.UpdateBinaryUploadConfigResponse_builder{}.Build(), nil
}

func binaryUploadConfigSchemas(t *testing.T, r *BinaryUploadConfigSettingsResource) (resource.SchemaResponse, resource.IdentitySchemaResponse) {
	t.Helper()
	ctx := context.Background()
	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)
	return sResp, iResp
}

// TestBinaryUploadConfigReadWithNoBucket covers a tenant that reports no URL
// at all. bucket_url is required, and a configuration clears the bucket with
// the empty string, so Read must store "" rather than null or that
// configuration would plan a change on every run.
func TestBinaryUploadConfigReadWithNoBucket(t *testing.T) {
	ctx := context.Background()
	r := &BinaryUploadConfigSettingsResource{client: &fakeBinaryUploadConfigClient{}}
	sResp, iResp := binaryUploadConfigSchemas(t, r)

	req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, BinaryUploadConfigSettingsResourceModel{BucketUrl: types.StringValue("")}); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &resource.ReadResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	var got BinaryUploadConfigSettingsResourceModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	if got.BucketUrl.IsNull() || got.BucketUrl.ValueString() != "" {
		t.Errorf("bucket_url: got %v, want the empty string", got.BucketUrl)
	}
}

// TestBinaryUploadConfigUpdateClearsBucket checks that clearing the bucket
// sends bucket_url as an explicit empty string. UpdateBinaryUploadConfig
// leaves the setting alone when the field is absent, so dropping an empty
// value from the request would leave binary upload on.
func TestBinaryUploadConfigUpdateClearsBucket(t *testing.T) {
	ctx := context.Background()
	stored := "gs://bucket"
	fake := &fakeBinaryUploadConfigClient{stored: &stored}
	r := &BinaryUploadConfigSettingsResource{client: fake}
	sResp, iResp := binaryUploadConfigSchemas(t, r)

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: sResp.Schema},
		State: tfsdk.State{Schema: sResp.Schema},
	}
	if diags := req.Plan.Set(ctx, BinaryUploadConfigSettingsResourceModel{BucketUrl: types.StringValue("")}); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	if diags := req.State.Set(ctx, BinaryUploadConfigSettingsResourceModel{BucketUrl: types.StringValue(stored)}); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags)
	}
	resp := &resource.UpdateResponse{
		State:    tfsdk.State{Schema: sResp.Schema},
		Identity: &tfsdk.ResourceIdentity{Schema: iResp.IdentitySchema},
	}
	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error diags: %v", resp.Diagnostics)
	}

	if len(fake.updates) != 1 {
		t.Fatalf("UpdateBinaryUploadConfig calls = %d, want 1", len(fake.updates))
	}
	if sent := fake.updates[0]; !sent.HasBucketUrl() || sent.GetBucketUrl() != "" {
		t.Errorf("request: has bucket_url %v, value %q; want an explicit empty string", sent.HasBucketUrl(), sent.GetBucketUrl())
	}
}
