// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

var _ resource.Resource = &MTLSCASettingsResource{}
var _ resource.ResourceWithConfigure = &MTLSCASettingsResource{}
var _ resource.ResourceWithImportState = &MTLSCASettingsResource{}
var _ resource.ResourceWithIdentity = &MTLSCASettingsResource{}

func NewMTLSCASettingsResource() resource.Resource {
	return &MTLSCASettingsResource{}
}

type MTLSCASettingsResource struct {
	client svcpb.WorkshopServiceClient
}

type MTLSCASettingsIdentityModel struct {
	Id types.String `tfsdk:"id"`
}

type MTLSCASettingsResourceModel struct {
	CertificatesPem types.Set `tfsdk:"certificates_pem"`
}

func (r *MTLSCASettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workshop_settings_mtls_cas"
}

func (r *MTLSCASettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "The nps_workshop_settings_mtls_cas resource manages the certificate authorities Workshop trusts for mTLS authentication of Santa. Santa can sync over mTLS when nps_workshop_settings_sync_auth enables it and Santa's client certificate is signed by one of these CAs. You need the read:settings and write:settings permissions. This is a singleton resource, one per tenant, and it manages the tenant's whole CA list: every apply, including the first, adds the configured CAs and removes any others. It adds before it removes, so swapping one CA for another never leaves a moment when neither is trusted. Destroying it removes it from state and leaves the tenant's CAs as they were.",
		MarkdownDescription: "The `nps_workshop_settings_mtls_cas` resource manages the certificate authorities Workshop trusts for mTLS authentication of Santa. Santa can sync over mTLS when `nps_workshop_settings_sync_auth` enables it and Santa's client certificate is signed by one of these CAs.\n\nYou need the `read:settings` and `write:settings` permissions.\n\nThis is a singleton resource, one per tenant, and it manages the tenant's whole CA list: every apply, including the first, adds the configured CAs and removes any others. It adds before it removes, so swapping one CA for another never leaves a moment when neither is trusted. Destroying it removes it from state and leaves the tenant's CAs as they were.",

		Attributes: map[string]schema.Attribute{
			"certificates_pem": schema.SetAttribute{
				Description:         "PEM-encoded CA certificates, one certificate per entry. Entries are compared by certificate, so PEM formatting such as line endings doesn't plan a change. An empty set removes every CA.",
				MarkdownDescription: "PEM-encoded CA certificates, one certificate per entry. Entries are compared by certificate, so PEM formatting such as line endings doesn't plan a change. An empty set removes every CA.",
				Required:            true,
				ElementType:         types.StringType,
				Validators: []validator.Set{
					mtlsCAsValidator{},
				},
			},
		},
	}
}

func (r *MTLSCASettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *MTLSCASettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data MTLSCASettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Created mTLS CA settings resource")
	resp.Diagnostics.Append(resp.Identity.Set(ctx, MTLSCASettingsIdentityModel{Id: types.StringValue("mtls_cas")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *MTLSCASettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state MTLSCASettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listed, err := r.list(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Failed to list mTLS CAs: %v", err))
		return
	}

	var prior []string
	if !state.CertificatesPem.IsNull() && !state.CertificatesPem.IsUnknown() {
		resp.Diagnostics.Append(state.CertificatesPem.ElementsAs(ctx, &prior, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	certs, d := types.SetValueFrom(ctx, types.StringType, mtlsCAsForState(prior, listed))
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.Identity.Set(ctx, MTLSCASettingsIdentityModel{Id: types.StringValue("mtls_cas")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &MTLSCASettingsResourceModel{CertificatesPem: certs})...)
}

func (r *MTLSCASettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan MTLSCASettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated mTLS CA settings")
	resp.Diagnostics.Append(resp.Identity.Set(ctx, MTLSCASettingsIdentityModel{Id: types.StringValue("mtls_cas")})...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MTLSCASettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "Removed mTLS CA settings from Terraform state (server-side configuration unchanged)")
}

func (r *MTLSCASettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.Set(ctx, &MTLSCASettingsResourceModel{
		CertificatesPem: types.SetValueMust(types.StringType, []attr.Value{}),
	})...)
}

func (r *MTLSCASettingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
			},
		},
	}
}

func (r *MTLSCASettingsResource) list(ctx context.Context) ([]string, error) {
	ret, err := r.client.ListmTLSCAs(ctx, apipb.ListmTLSCAsRequest_builder{}.Build())
	if err != nil {
		return nil, err
	}
	listed := make([]string, 0, len(ret.GetCertificatesPem()))
	for _, c := range ret.GetCertificatesPem() {
		listed = append(listed, string(c))
	}
	return listed, nil
}

// set makes the tenant's CA list match the model. The API only adds or removes
// one CA at a time, so set adds the missing CAs before it removes the others:
// swapping one CA for another never leaves a moment when neither is trusted.
// It removes a CA by sending back the bytes Workshop listed, which match
// however Workshop compares them.
func (r *MTLSCASettingsResource) set(ctx context.Context, m *MTLSCASettingsResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	var want []string
	diags.Append(m.CertificatesPem.ElementsAs(ctx, &want, false)...)
	if diags.HasError() {
		return diags
	}

	listed, err := r.list(ctx)
	if err != nil {
		diags.AddError("Client Error", fmt.Sprintf("Failed to list mTLS CAs: %v", err))
		return diags
	}

	have := make(map[string]bool, len(listed))
	for _, l := range listed {
		have[certificateKey(l)] = true
	}

	wanted := make(map[string]bool, len(want))
	for _, w := range want {
		key := certificateKey(w)
		wanted[key] = true
		if have[key] {
			continue
		}
		if _, err := r.client.AddmTLSCA(ctx, apipb.AddmTLSCARequest_builder{CertificatePem: []byte(w)}.Build()); err != nil {
			diags.AddError("Client Error", fmt.Sprintf("Failed to add mTLS CA %s: %v", certificateSubject(w), err))
			return diags
		}
		have[key] = true
	}

	for _, l := range listed {
		if wanted[certificateKey(l)] {
			continue
		}
		if _, err := r.client.RemovemTLSCA(ctx, apipb.RemovemTLSCARequest_builder{CertificatePem: []byte(l)}.Build()); err != nil {
			diags.AddError("Client Error", fmt.Sprintf("Failed to remove mTLS CA %s: %v", certificateSubject(l), err))
			return diags
		}
	}
	return diags
}

// mtlsCAsForState returns the CAs Workshop listed, each written the way the
// prior state wrote it when the certificate is the same. Workshop may not
// return a PEM byte for byte as it was sent, and storing its version would plan
// a change against the config on every refresh.
func mtlsCAsForState(prior, listed []string) []string {
	priorByKey := make(map[string]string, len(prior))
	for _, p := range prior {
		priorByKey[certificateKey(p)] = p
	}

	certs := make([]string, 0, len(listed))
	seen := make(map[string]bool, len(listed))
	for _, l := range listed {
		key := certificateKey(l)
		if seen[key] {
			continue
		}
		seen[key] = true
		if p, ok := priorByKey[key]; ok {
			l = p
		}
		certs = append(certs, l)
	}
	return certs
}

// parsePEMCertificate parses s as exactly one PEM-encoded X.509 certificate.
func parsePEMCertificate(s string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("the PEM block is %q, not CERTIFICATE", block.Type)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("there is data after the certificate; give each certificate its own entry")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the certificate doesn't parse: %v", err)
	}
	return cert, nil
}

// certificateKey identifies a CA by its DER encoding, so the same certificate
// matches however its PEM is formatted. A PEM that doesn't parse, which only
// Workshop could return since config is validated, is keyed by its trimmed text.
func certificateKey(s string) string {
	if cert, err := parsePEMCertificate(s); err == nil {
		return string(cert.Raw)
	}
	return strings.TrimSpace(s)
}

// certificateSubject names a CA in diagnostics.
func certificateSubject(s string) string {
	cert, err := parsePEMCertificate(s)
	if err != nil {
		return "(unparseable certificate)"
	}
	return fmt.Sprintf("%q", cert.Subject.String())
}

// mtlsCAsValidator rejects at plan time what Workshop would reject on apply or
// what set would mishandle: an entry that isn't exactly one PEM certificate,
// and the same certificate listed twice with different formatting.
type mtlsCAsValidator struct{}

func (mtlsCAsValidator) Description(context.Context) string {
	return "each entry must be one PEM-encoded certificate, and no certificate may be listed twice"
}

func (v mtlsCAsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (mtlsCAsValidator) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	seen := make(map[string]bool)
	for _, elem := range req.ConfigValue.Elements() {
		s, ok := elem.(types.String)
		if !ok || s.IsNull() || s.IsUnknown() {
			continue
		}
		cert, err := parsePEMCertificate(s.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(req.Path.AtSetValue(elem), "Invalid CA Certificate", err.Error())
			continue
		}
		if seen[string(cert.Raw)] {
			resp.Diagnostics.AddAttributeError(req.Path.AtSetValue(elem), "Duplicate CA Certificate", fmt.Sprintf("Certificate %s is listed more than once.", certificateSubject(s.ValueString())))
		}
		seen[string(cert.Raw)] = true
	}
}
