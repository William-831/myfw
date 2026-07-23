package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// TestRegistrationEndToEnd exercises the design § 13.3.2 flow end-to-end:
//  1. Admin mints a one-time bootstrap token via REST.
//  2. Agent connects to gRPC WITHOUT a client cert and calls Register.
//  3. Controller returns a signed client cert; node stored PENDING.
//  4. Using that new cert, the Agent can reach an authenticated RPC
//     (interceptor lets it through — the stub method itself returns
//     Unimplemented, not Unauthenticated).
//  5. Re-using the same bootstrap token is rejected.
//  6. REST approve transitions PENDING -> ACTIVE.
func TestRegistrationEndToEnd(t *testing.T) {
	grpcAddr, cfg, gdb := startTestServer(t)

	// Run the Web handler in-process against the same DB.
	webSrv := httptest.NewServer(BuildWebHandler(gdb, cfg.Bootstrap.TokenTTL))
	t.Cleanup(webSrv.Close)

	// --- 1. mint bootstrap token via REST ---
	tokResp := postJSON(t, webSrv.URL, "/api/v1/nodes/bootstrap", `{"note":"e2e"}`)
	token, _ := tokResp["token"].(string)
	if token == "" {
		t.Fatalf("no token in response: %v", tokResp)
	}

	// --- 2. Register over gRPC with NO client cert ---
	candidateID := "n_e2e_candidate"
	csrPEM, keyPEM := generateCSR(t, "unused")

	pool := caPool(t, cfg.Server.GRPC.TLS.CAFile)
	noCertConn := dialTLS(t, grpcAddr, pool, nil)
	defer noCertConn.Close()

	regClient := myfwv1.NewRegistrationClient(noCertConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := regClient.Register(ctx, &myfwv1.RegisterRequest{
		BootstrapToken: token,
		CandidateId:    candidateID,
		CsrPem:         csrPEM,
		Fingerprint: &myfwv1.MachineFingerprint{
			MachineId: "mid-e2e",
			Hostname:  "vm-e2e",
			Arch:      "amd64",
		},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.NodeId != candidateID {
		t.Fatalf("expected candidate id to be adopted, got %q", resp.NodeId)
	}
	if resp.NodeStatus != "PENDING" {
		t.Fatalf("expected PENDING, got %q", resp.NodeStatus)
	}
	if len(resp.ClientCertPem) == 0 {
		t.Fatal("no client cert returned")
	}

	// --- 3. Authenticated call with the freshly-signed cert ---
	clientCert, err := tls.X509KeyPair(resp.ClientCertPem, keyPEM)
	if err != nil {
		t.Fatalf("assemble client keypair: %v", err)
	}
	authConn := dialTLS(t, grpcAddr, pool, &clientCert)
	defer authConn.Close()

	// RenewCert is a stub -> Unimplemented, which proves the interceptor
	// let us through the auth layer (it would return Unauthenticated otherwise).
	_, err = myfwv1.NewRegistrationClient(authConn).RenewCert(ctx,
		&myfwv1.RenewCertRequest{NodeId: resp.NodeId})
	if err == nil {
		t.Fatal("expected some error from stub RenewCert")
	}
	if got := status.Code(err); got == codes.Unauthenticated {
		t.Fatalf("auth interceptor rejected valid cert: %v", err)
	} else if got != codes.Unimplemented {
		t.Fatalf("unexpected code %v: %v", got, err)
	}

	// --- 4. Token is single-use ---
	_, err = regClient.Register(ctx, &myfwv1.RegisterRequest{
		BootstrapToken: token,
		CandidateId:    "n_second",
		CsrPem:         csrPEM,
	})
	if err == nil {
		t.Fatal("expected token reuse to fail")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied on token reuse, got %v: %v", got, err)
	}

	// --- 5. PENDING -> ACTIVE via REST approve ---
	postJSON(t, webSrv.URL, "/api/v1/nodes/"+resp.NodeId+"/approve", "")
	list := getJSON(t, webSrv.URL, "/api/v1/nodes?status=ACTIVE")
	nodes, _ := list["nodes"].([]any)
	found := false
	for _, n := range nodes {
		if m, ok := n.(map[string]any); ok && m["id"] == resp.NodeId {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("approved node %q not found in ACTIVE list", resp.NodeId)
	}
}

// --- helpers ---------------------------------------------------------------

func postJSON(t *testing.T, base, path, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(base+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return decodeJSON(t, resp)
}

func getJSON(t *testing.T, base, path string) map[string]any {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return decodeJSON(t, resp)
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	if len(body) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode: %v (%s)", err, string(body))
	}
	return m
}

func dialTLS(t *testing.T, addr string, pool *x509.CertPool, clientCert *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
	}
	if clientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*clientCert}
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// generateCSR builds a fresh EC keypair and returns a PEM CSR + PEM private
// key that pairs with the cert we'll get back.
func generateCSR(t *testing.T, cn string) (csrPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM
}
