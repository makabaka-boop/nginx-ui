package site

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xJacky/Nginx-UI/internal/cert"
	"github.com/0xJacky/Nginx-UI/internal/nginx"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/query"
	"github.com/0xJacky/Nginx-UI/settings"
	"github.com/go-acme/lego/v5/certcrypto"
)

// batchReplaceCertFixture holds the on-disk paths and database record of a
// certificate registered in the test environment.
type batchReplaceCertFixture struct {
	record   *model.Cert
	certPath string
	keyPath  string
}

func createBatchReplaceCert(t *testing.T, env certificateMigrationTestEnv, dirName string,
	dnsNames []string) batchReplaceCertFixture {
	t.Helper()

	certPEM, keyPEM, err := cert.GenerateSelfSigned(cert.SelfSignedOptions{
		CommonName: dnsNames[0],
		DNSNames:   dnsNames,
		KeyType:    certcrypto.EC256,
	})
	if err != nil {
		t.Fatalf("generate certificate %s: %v", dirName, err)
	}
	dir := filepath.Join(env.confDir, "ssl", dirName)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, "private.key")
	if err = os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	record := &model.Cert{
		Name:                  dirName,
		Filename:              dirName,
		Domains:               dnsNames,
		SSLCertificatePath:    certPath,
		SSLCertificateKeyPath: keyPath,
	}
	if err = env.db.Create(record).Error; err != nil {
		t.Fatalf("create cert record: %v", err)
	}
	return batchReplaceCertFixture{record: record, certPath: certPath, keyPath: keyPath}
}

// createFutureCertificate writes a certificate whose validity window starts
// in the future so the preview can reject it.
func createFutureCertificate(t *testing.T, env certificateMigrationTestEnv, dirName string,
	dnsNames []string) batchReplaceCertFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := filepath.Join(env.confDir, "ssl", dirName)
	if err = os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, "private.key")
	if err = os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err = os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	record := &model.Cert{
		Name:                  dirName,
		Filename:              dirName,
		Domains:               dnsNames,
		SSLCertificatePath:    certPath,
		SSLCertificateKeyPath: keyPath,
	}
	if err = env.db.Create(record).Error; err != nil {
		t.Fatalf("create cert record: %v", err)
	}
	return batchReplaceCertFixture{record: record, certPath: certPath, keyPath: keyPath}
}

func batchReplaceServerContent(certPath, keyPath, serverName string) string {
	return "server {\n    listen 443 ssl;\n    server_name " + serverName + ";\n" +
		"    ssl_certificate " + certPath + ";\n" +
		"    ssl_certificate_key " + keyPath + ";\n}\n"
}

func writeBatchReplaceSite(t *testing.T, env certificateMigrationTestEnv, name, content string, enabled bool) {
	t.Helper()
	path := filepath.Join(env.confDir, "sites-available", name)
	writeUsageTestFile(t, path, content)
	if enabled {
		if err := os.Symlink(path, filepath.Join(env.confDir, "sites-enabled", name)); err != nil {
			t.Fatalf("enable %s: %v", name, err)
		}
	}
}

func previewSiteByName(t *testing.T, preview *CertificateBatchReplacePreview,
	name string) *CertificateBatchReplaceSite {
	t.Helper()
	for _, sitePreview := range preview.Sites {
		if sitePreview.Name == name {
			return sitePreview
		}
	}
	t.Fatalf("site %s missing from preview: %+v", name, preview.Sites)
	return nil
}

func TestCertificateBatchReplacePreview(t *testing.T) {
	env := setupCertificateMigrationTest(t)

	oldCert := createBatchReplaceCert(t, env, "old", []string{"example.com", "www.example.com"})
	newCert := createBatchReplaceCert(t, env, "new",
		[]string{"example.com", "www.example.com", "api.example.com"})
	otherCert := createBatchReplaceCert(t, env, "other", []string{"other.test"})

	writeBatchReplaceSite(t, env, "eligible.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com www.example.com"), true)
	writeBatchReplaceSite(t, env, "disabled.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "www.example.com"), false)
	writeBatchReplaceSite(t, env, "relative.conf",
		batchReplaceServerContent("ssl/old/fullchain.cer", "ssl/old/private.key", "example.com"), true)
	writeBatchReplaceSite(t, env, "dual.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com")+
			batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "api.example.com"), true)

	// Maintenance sites are excluded.
	writeBatchReplaceSite(t, env, "maintenance.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), false)
	writeUsageTestFile(t,
		filepath.Join(env.confDir, "sites-enabled", "maintenance.conf"+MaintenanceSuffix), "")

	// Two ssl_certificate directives in one server block.
	writeBatchReplaceSite(t, env, "multi.conf", "server {\n    listen 443 ssl;\n    server_name example.com;\n"+
		"    ssl_certificate "+oldCert.certPath+";\n"+
		"    ssl_certificate "+otherCert.certPath+";\n"+
		"    ssl_certificate_key "+oldCert.keyPath+";\n}\n", false)

	// Old certificate paired with a foreign private key.
	foreignKey := filepath.Join(env.confDir, "ssl", "foreign.key")
	writeUsageTestFile(t, foreignKey, "not-a-key")
	writeBatchReplaceSite(t, env, "wrongkey.conf", "server {\n    listen 443 ssl;\n    server_name example.com;\n"+
		"    ssl_certificate "+oldCert.certPath+";\n"+
		"    ssl_certificate_key "+foreignKey+";\n}\n", false)

	// The new certificate does not cover the server name.
	writeBatchReplaceSite(t, env, "uncovered.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "uncovered.test"), false)

	// Reference outside server blocks.
	writeBatchReplaceSite(t, env, "outside.conf",
		"ssl_certificate "+oldCert.certPath+";\nssl_certificate_key "+oldCert.keyPath+";\n"+
			"server {\n    listen 80;\n    server_name example.com;\n}\n", false)

	// Only another certificate: must not show up in the preview.
	writeBatchReplaceSite(t, env, "other-only.conf",
		batchReplaceServerContent(otherCert.certPath, otherCert.keyPath, "other.test"), false)

	// Managed by an ingress.
	writeBatchReplaceSite(t, env, "managed.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), false)
	if err := env.db.Create(&model.Site{
		Path:      filepath.Join(env.confDir, "sites-available", "managed.conf"),
		ManagedBy: "ingress:web",
	}).Error; err != nil {
		t.Fatalf("create managed site: %v", err)
	}

	// Explicit cluster sync targets.
	writeBatchReplaceSite(t, env, "synced.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), false)
	if err := env.db.Create(&model.Site{
		Path:        filepath.Join(env.confDir, "sites-available", "synced.conf"),
		SyncNodeIDs: []uint64{1},
	}).Error; err != nil {
		t.Fatalf("create synced site: %v", err)
	}

	// Remote-deploy namespace.
	writeBatchReplaceSite(t, env, "remote.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), false)
	namespace := &model.Namespace{Name: "remote", DeployMode: model.DeployModeRemote}
	if err := env.db.Create(namespace).Error; err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	if err := env.db.Create(&model.Site{
		Path:        filepath.Join(env.confDir, "sites-available", "remote.conf"),
		NamespaceID: namespace.ID, RemoteEnabled: true,
	}).Error; err != nil {
		t.Fatalf("create remote site: %v", err)
	}

	preview, err := PreviewCertificateBatchReplace(oldCert.record.ID, newCert.record.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.NewCertificateHash == "" {
		t.Fatal("new certificate hash must be returned")
	}
	if preview.NewCertificatePath != newCert.certPath {
		t.Fatalf("new path = %s, want %s", preview.NewCertificatePath, newCert.certPath)
	}

	selectable := map[string]bool{}
	for _, sitePreview := range preview.Sites {
		selectable[sitePreview.Name] = sitePreview.Selectable
	}
	for _, name := range []string{"eligible.conf", "disabled.conf", "relative.conf", "dual.conf"} {
		if !selectable[name] {
			sitePreview := previewSiteByName(t, preview, name)
			t.Fatalf("%s must be selectable, reason = %+v", name, sitePreview.Reason)
		}
	}
	otherOnlyPresent := false
	for _, sitePreview := range preview.Sites {
		if sitePreview.Name == "other-only.conf" {
			otherOnlyPresent = true
		}
	}
	if otherOnlyPresent {
		t.Fatal("a site without an old-certificate reference must be absent")
	}

	ineligible := map[string]string{
		"maintenance.conf": batchReplaceReasonMaintenance,
		"multi.conf":       batchReplaceReasonMultipleDirectives,
		"wrongkey.conf":    batchReplaceReasonPairMismatch,
		"uncovered.conf":   batchReplaceReasonNamesNotCovered,
		"outside.conf":     batchReplaceReasonUnsupportedReference,
		"managed.conf":     batchReplaceReasonManaged,
		"synced.conf":      batchReplaceReasonSyncTargets,
		"remote.conf":      batchReplaceReasonRemoteDeploy,
	}
	for name, code := range ineligible {
		sitePreview := previewSiteByName(t, preview, name)
		if sitePreview.Selectable {
			t.Fatalf("%s must not be selectable", name)
		}
		if sitePreview.Reason == nil || sitePreview.Reason.Code != code {
			t.Fatalf("%s reason = %+v, want %s", name, sitePreview.Reason, code)
		}
	}

	eligible := previewSiteByName(t, preview, "eligible.conf")
	if eligible.Status != StatusEnabled || len(eligible.Servers) != 1 {
		t.Fatalf("eligible servers/status = %+v/%s", eligible.Servers, eligible.Status)
	}
	foundAdd, foundRemove := false, false
	for _, line := range eligible.Diff {
		if line.Type == "add" && strings.Contains(line.Text, newCert.certPath) {
			foundAdd = true
		}
		if line.Type == "remove" && strings.Contains(line.Text, oldCert.certPath) {
			foundRemove = true
		}
	}
	if !foundAdd || !foundRemove {
		t.Fatalf("diff must show the path swap: %+v", eligible.Diff)
	}
	if !strings.Contains(eligible.newContent, newCert.certPath) ||
		strings.Contains(eligible.newContent, oldCert.certPath) {
		t.Fatal("rewritten content must reference only the new certificate")
	}
	// Unrelated content is preserved.
	if !strings.Contains(eligible.newContent, "server_name example.com www.example.com;") {
		t.Fatal("server_name must be preserved")
	}

	dual := previewSiteByName(t, preview, "dual.conf")
	if len(dual.Servers) != 2 {
		t.Fatalf("dual server count = %d, want 2", len(dual.Servers))
	}
	adds := 0
	for _, line := range dual.Diff {
		if line.Type == "add" {
			adds++
		}
	}
	if adds != 4 {
		t.Fatalf("dual diff add lines = %d, want 4", adds)
	}

	relative := previewSiteByName(t, preview, "relative.conf")
	if !strings.Contains(relative.newContent, newCert.certPath) {
		t.Fatal("relative references must be rewritten to absolute new paths")
	}
}

func TestCertificateBatchReplacePreviewRejectsBadInput(t *testing.T) {
	env := setupCertificateMigrationTest(t)

	oldCert := createBatchReplaceCert(t, env, "old", []string{"example.com"})
	newCert := createBatchReplaceCert(t, env, "new", []string{"example.com"})
	future := createFutureCertificate(t, env, "future", []string{"example.com"})

	if _, err := PreviewCertificateBatchReplace(oldCert.record.ID, oldCert.record.ID); err == nil {
		t.Fatal("using the same certificate for old and new must fail")
	}
	if _, err := PreviewCertificateBatchReplace(oldCert.record.ID, future.record.ID); err == nil {
		t.Fatal("a certificate outside its validity window must fail")
	}

	mismatched := &model.Cert{
		Name:                  "mismatched",
		Filename:              "mismatched",
		SSLCertificatePath:    newCert.certPath,
		SSLCertificateKeyPath: oldCert.keyPath,
	}
	if err := env.db.Create(mismatched).Error; err != nil {
		t.Fatalf("create mismatched record: %v", err)
	}
	if _, err := PreviewCertificateBatchReplace(oldCert.record.ID, mismatched.ID); err == nil {
		t.Fatal("a certificate/key pair that does not match must fail")
	}
}

func TestApplyCertificateBatchReplace(t *testing.T) {
	env := setupCertificateMigrationTest(t)

	oldCert := createBatchReplaceCert(t, env, "old", []string{"example.com", "www.example.com"})
	newCert := createBatchReplaceCert(t, env, "new", []string{"example.com", "www.example.com"})

	writeBatchReplaceSite(t, env, "eligible.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), true)
	writeBatchReplaceSite(t, env, "disabled.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "www.example.com"), false)
	writeBatchReplaceSite(t, env, "dual.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com")+
			batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "www.example.com"), true)

	preview, err := PreviewCertificateBatchReplace(oldCert.record.ID, newCert.record.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	selectHash := func(name string) string {
		return previewSiteByName(t, preview, name).ContentHash
	}

	updated, err := ApplyCertificateBatchReplace(oldCert.record.ID, newCert.record.ID,
		preview.NewCertificateHash, []CertificateBatchReplaceSelection{
			{Name: "eligible.conf", ContentHash: selectHash("eligible.conf")},
			{Name: "disabled.conf", ContentHash: selectHash("disabled.conf")},
		})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(updated) != 2 {
		t.Fatalf("updated = %v, want 2 sites", updated)
	}

	for _, name := range []string{"eligible.conf", "disabled.conf"} {
		content, err := nginx.ReadFile(filepath.Join(env.confDir, "sites-available", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(content)
		if !strings.Contains(text, newCert.certPath) || !strings.Contains(text, newCert.keyPath) {
			t.Fatalf("%s must reference the new pair: %s", name, text)
		}
		if strings.Contains(text, oldCert.certPath) || strings.Contains(text, oldCert.keyPath) {
			t.Fatalf("%s must not reference the old pair", name)
		}
	}
	// The enabled symlink and the untouched site are preserved.
	if target, err := os.Readlink(filepath.Join(env.confDir, "sites-enabled", "eligible.conf")); err != nil ||
		target != filepath.Join(env.confDir, "sites-available", "eligible.conf") {
		t.Fatalf("enabled symlink changed: %q (%v)", target, err)
	}
	dual, err := os.ReadFile(filepath.Join(env.confDir, "sites-available", "dual.conf"))
	if err != nil {
		t.Fatalf("read dual: %v", err)
	}
	if !strings.Contains(string(dual), oldCert.certPath) {
		t.Fatal("unselected sites must stay untouched")
	}
	// A history backup was written for the changed file.
	backupCount, err := query.ConfigBackup.Count()
	if err != nil {
		t.Fatalf("count backups: %v", err)
	}
	if backupCount == 0 {
		t.Fatal("a configuration history record must be created")
	}

	// The certificate records themselves are untouched.
	if err := env.db.First(&model.Cert{}, oldCert.record.ID).Error; err != nil {
		t.Fatalf("old cert record missing: %v", err)
	}
}

func TestApplyCertificateBatchReplaceRejectsStalePreview(t *testing.T) {
	env := setupCertificateMigrationTest(t)

	oldCert := createBatchReplaceCert(t, env, "old", []string{"example.com"})
	newCert := createBatchReplaceCert(t, env, "new", []string{"example.com"})
	writeBatchReplaceSite(t, env, "eligible.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), true)

	preview, err := PreviewCertificateBatchReplace(oldCert.record.ID, newCert.record.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	hash := previewSiteByName(t, preview, "eligible.conf").ContentHash

	// The configuration changed after the preview.
	sitePath := filepath.Join(env.confDir, "sites-available", "eligible.conf")
	writeUsageTestFile(t, sitePath,
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com")+"# changed\n")

	if _, err = ApplyCertificateBatchReplace(oldCert.record.ID, newCert.record.ID,
		preview.NewCertificateHash, []CertificateBatchReplaceSelection{
			{Name: "eligible.conf", ContentHash: hash},
		}); err != ErrBatchReplacePreviewStale {
		t.Fatalf("stale content error = %v, want ErrBatchReplacePreviewStale", err)
	}

	if _, err = ApplyCertificateBatchReplace(oldCert.record.ID, newCert.record.ID,
		"stale-hash", []CertificateBatchReplaceSelection{
			{Name: "eligible.conf", ContentHash: hash},
		}); err != ErrBatchReplacePreviewStale {
		t.Fatalf("stale cert hash error = %v, want ErrBatchReplacePreviewStale", err)
	}
}

func TestApplyCertificateBatchReplaceRollsBackOnTestFailure(t *testing.T) {
	env := setupCertificateMigrationTest(t)

	oldCert := createBatchReplaceCert(t, env, "old", []string{"example.com"})
	newCert := createBatchReplaceCert(t, env, "new", []string{"example.com"})
	writeBatchReplaceSite(t, env, "eligible.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), true)
	writeBatchReplaceSite(t, env, "second.conf",
		batchReplaceServerContent(oldCert.certPath, oldCert.keyPath, "example.com"), true)

	preview, err := PreviewCertificateBatchReplace(oldCert.record.ID, newCert.record.ID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}

	// Make `nginx -t` reject the configuration for this apply only.
	originalTestCmd := settings.NginxSettings.TestConfigCmd
	settings.NginxSettings.TestConfigCmd = "false"
	defer func() { settings.NginxSettings.TestConfigCmd = originalTestCmd }()

	_, err = ApplyCertificateBatchReplace(oldCert.record.ID, newCert.record.ID,
		preview.NewCertificateHash, []CertificateBatchReplaceSelection{
			{Name: "eligible.conf", ContentHash: previewSiteByName(t, preview, "eligible.conf").ContentHash},
			{Name: "second.conf", ContentHash: previewSiteByName(t, preview, "second.conf").ContentHash},
		})
	if err == nil {
		t.Fatal("a rejected nginx test must fail the batch")
	}

	for _, name := range []string{"eligible.conf", "second.conf"} {
		content, err := os.ReadFile(filepath.Join(env.confDir, "sites-available", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(content), oldCert.certPath) {
			t.Fatalf("%s must be rolled back to the old certificate", name)
		}
		if strings.Contains(string(content), newCert.certPath) {
			t.Fatalf("%s must not reference the new certificate after rollback", name)
		}
	}
}
