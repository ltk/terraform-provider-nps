// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

// testCAPEM returns a self-signed CA certificate for cn, PEM-encoded the way Go
// writes it: 64-column lines and a trailing newline.
func testCAPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// reformatPEM writes the same certificate the way another encoder might, with
// CRLF line endings and no trailing newline.
func reformatPEM(s string) string {
	return strings.TrimSuffix(strings.ReplaceAll(s, "\n", "\r\n"), "\r\n")
}

func testCN(t *testing.T, s []byte) string {
	t.Helper()
	block, _ := pem.Decode(s)
	if block == nil {
		t.Fatalf("not PEM: %q", s)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert.Subject.CommonName
}

type fakeMTLSCAClient struct {
	svcpb.WorkshopServiceClient

	t      *testing.T
	stored [][]byte
	calls  []string
}

func (f *fakeMTLSCAClient) ListmTLSCAs(ctx context.Context, in *apipb.ListmTLSCAsRequest, _ ...grpc.CallOption) (*apipb.ListmTLSCAsResponse, error) {
	return apipb.ListmTLSCAsResponse_builder{CertificatesPem: f.stored}.Build(), nil
}

func (f *fakeMTLSCAClient) AddmTLSCA(ctx context.Context, in *apipb.AddmTLSCARequest, _ ...grpc.CallOption) (*apipb.AddmTLSCAResponse, error) {
	f.calls = append(f.calls, "add "+testCN(f.t, in.GetCertificatePem()))
	f.stored = append(f.stored, in.GetCertificatePem())
	return apipb.AddmTLSCAResponse_builder{}.Build(), nil
}

// RemovemTLSCA matches the stored bytes exactly, the strictest way Workshop
// could compare them.
func (f *fakeMTLSCAClient) RemovemTLSCA(ctx context.Context, in *apipb.RemovemTLSCARequest, _ ...grpc.CallOption) (*apipb.RemovemTLSCAResponse, error) {
	for i, s := range f.stored {
		if bytes.Equal(s, in.GetCertificatePem()) {
			f.calls = append(f.calls, "remove "+testCN(f.t, s))
			f.stored = append(f.stored[:i], f.stored[i+1:]...)
			return apipb.RemovemTLSCAResponse_builder{}.Build(), nil
		}
	}
	return nil, status.Error(codes.NotFound, "no such CA")
}

func mtlsCASchemas(t *testing.T, r *MTLSCASettingsResource) (resource.SchemaResponse, resource.IdentitySchemaResponse) {
	t.Helper()
	ctx := context.Background()
	var sResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sResp)
	var iResp resource.IdentitySchemaResponse
	r.IdentitySchema(ctx, resource.IdentitySchemaRequest{}, &iResp)
	return sResp, iResp
}

func mtlsCAModel(certs ...string) MTLSCASettingsResourceModel {
	values := make([]attr.Value, 0, len(certs))
	for _, c := range certs {
		values = append(values, types.StringValue(c))
	}
	return MTLSCASettingsResourceModel{CertificatesPem: types.SetValueMust(types.StringType, values)}
}

// TestMTLSCAsUpdateAddsBeforeRemoving covers a rotation: Workshop holds keep
// and old in its own formatting, and the plan swaps old for new. The new CA has
// to be trusted before the old one goes, keep must be left alone although its
// bytes differ from the plan's, and old must be removed with the bytes Workshop
// listed.
func TestMTLSCAsUpdateAddsBeforeRemoving(t *testing.T) {
	ctx := context.Background()
	keep, old, next := testCAPEM(t, "keep"), testCAPEM(t, "old"), testCAPEM(t, "new")

	fake := &fakeMTLSCAClient{t: t, stored: [][]byte{[]byte(reformatPEM(keep)), []byte(reformatPEM(old))}}
	r := &MTLSCASettingsResource{client: fake}
	sResp, iResp := mtlsCASchemas(t, r)

	req := resource.UpdateRequest{
		Plan:  tfsdk.Plan{Schema: sResp.Schema},
		State: tfsdk.State{Schema: sResp.Schema},
	}
	if diags := req.Plan.Set(ctx, mtlsCAModel(keep, next)); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags)
	}
	if diags := req.State.Set(ctx, mtlsCAModel(keep, old)); diags.HasError() {
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

	if want := []string{"add new", "remove old"}; !reflect.DeepEqual(fake.calls, want) {
		t.Errorf("calls = %q, want %q", fake.calls, want)
	}
}

// TestMTLSCAsReadKeepsConfiguredPEM covers a refresh where Workshop returns a
// configured CA reformatted, plus a CA someone added outside Terraform. The
// configured CA must stay as config wrote it, or every plan would show a
// change. The other CA must appear, so the plan shows it being removed.
func TestMTLSCAsReadKeepsConfiguredPEM(t *testing.T) {
	ctx := context.Background()
	keep, extra := testCAPEM(t, "keep"), testCAPEM(t, "extra")

	r := &MTLSCASettingsResource{client: &fakeMTLSCAClient{t: t, stored: [][]byte{[]byte(reformatPEM(keep)), []byte(extra)}}}
	sResp, iResp := mtlsCASchemas(t, r)

	req := resource.ReadRequest{State: tfsdk.State{Schema: sResp.Schema}}
	if diags := req.State.Set(ctx, mtlsCAModel(keep)); diags.HasError() {
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

	var got MTLSCASettingsResourceModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("reading final state: %v", diags)
	}
	var certs []string
	if diags := got.CertificatesPem.ElementsAs(ctx, &certs, false); diags.HasError() {
		t.Fatalf("reading certificates_pem: %v", diags)
	}
	want := []string{keep, extra}
	sort.Strings(certs)
	sort.Strings(want)
	if !reflect.DeepEqual(certs, want) {
		t.Errorf("certificates_pem = %q, want %q", certs, want)
	}
}

func TestMTLSCAsValidator(t *testing.T) {
	ctx := context.Background()
	a, b := testCAPEM(t, "a"), testCAPEM(t, "b")
	publicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}))
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))

	r := &MTLSCASettingsResource{}
	sResp, _ := mtlsCASchemas(t, r)
	attribute, ok := sResp.Schema.Attributes["certificates_pem"].(schema.SetAttribute)
	if !ok {
		t.Fatalf("certificates_pem is not a set attribute")
	}

	for _, tc := range []struct {
		name    string
		certs   []string
		wantErr bool
	}{
		{"two certificates", []string{a, b}, false},
		{"no certificates", nil, false},
		{"not PEM", []string{"not a certificate"}, true},
		{"not a certificate block", []string{publicKey}, true},
		{"unparseable certificate", []string{garbage}, true},
		{"two certificates in one entry", []string{a + b}, true},
		{"one certificate twice", []string{a, reformatPEM(a)}, true},
	} {
		resp := &validator.SetResponse{}
		req := validator.SetRequest{Path: path.Root("certificates_pem"), ConfigValue: mtlsCAModel(tc.certs...).CertificatesPem}
		for _, v := range attribute.Validators {
			v.ValidateSet(ctx, req, resp)
		}
		if got := resp.Diagnostics.HasError(); got != tc.wantErr {
			t.Errorf("%s: got error=%v, want error=%v (%v)", tc.name, got, tc.wantErr, resp.Diagnostics)
		}
	}
}
