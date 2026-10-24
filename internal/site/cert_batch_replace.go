package site

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xJacky/Nginx-UI/internal/cert"
	"github.com/0xJacky/Nginx-UI/internal/config"
	"github.com/0xJacky/Nginx-UI/internal/nginx"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/query"
	"github.com/uozi-tech/cosy"
	"gorm.io/gorm"
)

// Reason codes explain why a site cannot participate in a batch certificate
// replacement. The frontend maps the codes to localized messages; Message is
// the English fallback.
const (
	batchReplaceReasonRemoteDeploy         = "remote_deploy"
	batchReplaceReasonManaged              = "managed"
	batchReplaceReasonSyncTargets          = "sync_targets_configured"
	batchReplaceReasonMaintenance          = "site_in_maintenance"
	batchReplaceReasonConfigUnparseable    = "config_unparseable"
	batchReplaceReasonMultipleDirectives   = "multiple_certificate_directives"
	batchReplaceReasonPairMismatch         = "certificate_pair_mismatch"
	batchReplaceReasonUnsupportedReference = "unsupported_reference"
	batchReplaceReasonNamesNotCovered      = "names_not_covered"
	batchReplaceReasonUnavailable          = "site_unavailable"
)

// CertificateBatchReplaceReason describes why a site is not selectable.
type CertificateBatchReplaceReason struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Params  map[string]string `json:"params,omitempty"`
}

// CertificateBatchReplaceServer summarizes a server block that directly
// references the old certificate.
type CertificateBatchReplaceServer struct {
	// Index is the zero-based position of the server block in the file.
	Index int `json:"index"`
	// Listen holds the parameters of every listen directive.
	Listen []string `json:"listen"`
	// ServerNames holds the literal server_name entries.
	ServerNames []string `json:"server_names"`
}

// CertificateBatchReplaceDiffLine is one line of the before/after preview.
type CertificateBatchReplaceDiffLine struct {
	// Type is "context", "remove", "add" or "spacer".
	Type  string `json:"type"`
	Text  string `json:"text"`
	OldNo int    `json:"old_no,omitempty"`
	NewNo int    `json:"new_no,omitempty"`
}

// CertificateBatchReplaceSite is the per-site preview row.
type CertificateBatchReplaceSite struct {
	Name        string                            `json:"name"`
	Status      Status                            `json:"status"`
	Selectable  bool                              `json:"selectable"`
	Reason      *CertificateBatchReplaceReason    `json:"reason,omitempty"`
	Servers     []CertificateBatchReplaceServer   `json:"servers,omitempty"`
	Diff        []CertificateBatchReplaceDiffLine `json:"diff,omitempty"`
	ContentHash string                            `json:"content_hash"`

	path       string
	newContent string
}

// CertificateBatchReplacePreview is the result of a preview request.
type CertificateBatchReplacePreview struct {
	OldCertificateID      uint64    `json:"old_certificate_id"`
	NewCertificateID      uint64    `json:"new_certificate_id"`
	OldCertificatePath    string    `json:"old_certificate_path"`
	OldCertificateKeyPath string    `json:"old_certificate_key_path"`
	NewCertificatePath    string    `json:"new_certificate_path"`
	NewCertificateKeyPath string    `json:"new_certificate_key_path"`
	NewNotBefore          time.Time `json:"new_not_before"`
	NewNotAfter           time.Time `json:"new_not_after"`
	// NewCertificateHash fingerprints the new certificate and key file bytes.
	// The confirm request echoes it so a replaced certificate file forces a
	// fresh preview.
	NewCertificateHash string                         `json:"new_certificate_hash"`
	Sites              []*CertificateBatchReplaceSite `json:"sites"`
}

// CertificateBatchReplaceSelection is one selected site of a confirm request.
type CertificateBatchReplaceSelection struct {
	Name        string `json:"name" binding:"required"`
	ContentHash string `json:"content_hash" binding:"required"`
}

func batchReplaceReason(code, message string, params map[string]string) *CertificateBatchReplaceReason {
	return &CertificateBatchReplaceReason{Code: code, Message: message, Params: params}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// resolveCertificateDirectivePath turns a textual ssl_certificate /
// ssl_certificate_key argument into a clean absolute path under the nginx
// configuration directory. Empty string means the value cannot be resolved
// statically (variables, data: and engine: resources).
func resolveCertificateDirectivePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "$") ||
		strings.HasPrefix(value, "data:") || strings.HasPrefix(value, "engine:") {
		return ""
	}
	if !filepath.IsAbs(value) {
		value = nginx.GetConfPath(value)
	}
	return filepath.Clean(value)
}

func unquoteDirectiveValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') ||
			(value[0] == '"' && value[len(value)-1] == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// pathsEqualOrSameFile reports whether two configured paths point at the same
// file. Clean-path equality handles the common case; the inode comparison
// covers symlinked aliases of the same certificate directory.
func pathsEqualOrSameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return false
	}
	return os.SameFile(infoA, infoB)
}

func loadCertRecord(id uint64) (*model.Cert, error) {
	c := query.Cert
	record, err := c.Where(c.ID.Eq(id)).First()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrBatchReplaceCertificateNotFound
	}
	if err != nil {
		return nil, err
	}
	return record, nil
}

func certificateFilesHash(certPath, keyPath string) (string, error) {
	certPEM, err := nginx.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	keyPEM, err := nginx.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	hasher.Write(certPEM)
	hasher.Write(keyPEM)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// PreviewCertificateBatchReplace scans sites-available for sites that directly
// reference the old certificate and computes what swapping the certificate and
// key paths for the new certificate would change. It never mutates state.
func PreviewCertificateBatchReplace(oldCertID, newCertID uint64) (*CertificateBatchReplacePreview, error) {
	if oldCertID == newCertID {
		return nil, ErrBatchReplaceSameCertificate
	}

	oldRecord, err := loadCertRecord(oldCertID)
	if err != nil {
		return nil, err
	}
	newRecord, err := loadCertRecord(newCertID)
	if err != nil {
		return nil, err
	}

	oldCertPath := filepath.Clean(strings.TrimSpace(oldRecord.SSLCertificatePath))
	oldKeyPath := filepath.Clean(strings.TrimSpace(oldRecord.SSLCertificateKeyPath))
	if oldRecord.SSLCertificatePath == "" || oldRecord.SSLCertificateKeyPath == "" {
		return nil, cosy.WrapErrorWithParams(ErrBatchReplaceCertificateUnusable,
			"the old certificate record has no configured file paths")
	}

	newCertPath := filepath.Clean(strings.TrimSpace(newRecord.SSLCertificatePath))
	newKeyPath := filepath.Clean(strings.TrimSpace(newRecord.SSLCertificateKeyPath))
	// LoadCertificatePair validates that both files exist below the nginx
	// configuration directory and that the key matches the certificate.
	pair, err := cert.LoadCertificatePair(newRecord.SSLCertificatePath, newRecord.SSLCertificateKeyPath)
	if err != nil {
		return nil, cosy.WrapErrorWithParams(ErrBatchReplaceCertificateUnusable, err.Error())
	}
	now := time.Now()
	if now.Before(pair.Leaf.NotBefore) {
		return nil, cosy.WrapErrorWithParams(ErrBatchReplaceCertificateUnusable,
			"the new certificate is not valid yet")
	}
	if !now.Before(pair.Leaf.NotAfter) {
		return nil, cosy.WrapErrorWithParams(ErrBatchReplaceCertificateUnusable,
			"the new certificate has expired")
	}

	newHash, err := certificateFilesHash(newRecord.SSLCertificatePath, newRecord.SSLCertificateKeyPath)
	if err != nil {
		return nil, err
	}

	preview := &CertificateBatchReplacePreview{
		OldCertificateID:      oldCertID,
		NewCertificateID:      newCertID,
		OldCertificatePath:    oldCertPath,
		OldCertificateKeyPath: oldKeyPath,
		NewCertificatePath:    newCertPath,
		NewCertificateKeyPath: newKeyPath,
		NewNotBefore:          pair.Leaf.NotBefore,
		NewNotAfter:           pair.Leaf.NotAfter,
		NewCertificateHash:    newHash,
	}

	entries, err := nginx.ReadDir(nginx.GetConfPath("sites-available"))
	if err != nil {
		if os.IsNotExist(err) {
			return preview, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path, errPath := ResolveAvailablePath(name)
		if errPath != nil {
			continue
		}
		contentBytes, errRead := nginx.ReadFile(path)
		if errRead != nil {
			continue
		}
		content := string(contentBytes)
		if !fileReferencesCertificate(content, oldCertPath) {
			continue
		}
		sitePreview := analyzeBatchReplaceSite(name, path, content, oldCertPath, oldKeyPath,
			newCertPath, newKeyPath, pair.Leaf)
		preview.Sites = append(preview.Sites, sitePreview)
	}

	return preview, nil
}

// fileReferencesCertificate reports whether an ssl_certificate directive in the
// file resolves to the old certificate. Variables and other dynamic values are
// ignored because they cannot be matched statically.
func fileReferencesCertificate(content, oldCertPath string) bool {
	values, err := nginx.DirectiveValues(content, "ssl_certificate")
	if err != nil {
		return false
	}
	for _, value := range values {
		if pathsEqualOrSameFile(resolveCertificateDirectivePath(value), oldCertPath) {
			return true
		}
	}
	return false
}

type matchedCertificateServer struct {
	index     int
	listen    []string
	names     []string
	certToken string
	keyToken  string
}

// analyzeBatchReplaceSite enforces every eligibility rule and, when the site is
// selectable, builds the rewritten configuration and its diff.
func analyzeBatchReplaceSite(name, path, content, oldCertPath, oldKeyPath,
	newCertPath, newKeyPath string, leaf *x509.Certificate) *CertificateBatchReplaceSite {
	result := &CertificateBatchReplaceSite{
		Name:        name,
		Status:      GetSiteStatus(name),
		ContentHash: sha256Hex([]byte(content)),
		path:        path,
	}
	fail := func(code, message string, params map[string]string) *CertificateBatchReplaceSite {
		result.Selectable = false
		result.Reason = batchReplaceReason(code, message, params)
		return result
	}

	siteModel, err := lookupSiteModel(path)
	if err != nil {
		return fail(batchReplaceReasonUnavailable,
			"The site cannot be analyzed: "+err.Error(),
			map[string]string{"error": err.Error()})
	}
	if siteModel != nil {
		if siteModel.Namespace.IsRemoteDeploy() {
			return fail(batchReplaceReasonRemoteDeploy,
				"The site is deployed to remote nodes only", nil)
		}
		if siteModel.ManagedBy != "" {
			return fail(batchReplaceReasonManaged,
				"The site is managed by "+siteModel.ManagedBy,
				map[string]string{"by": siteModel.ManagedBy})
		}
		// An empty own list means the site either has no cluster targets or
		// inherits the namespace targets; both are supported. Explicitly
		// configured targets must keep their references in sync manually.
		if len(siteModel.SyncNodeIDs) > 0 {
			return fail(batchReplaceReasonSyncTargets,
				"The site synchronizes to explicitly configured cluster nodes", nil)
		}
	}

	if result.Status == StatusMaintenance {
		return fail(batchReplaceReasonMaintenance, "The site is in maintenance mode", nil)
	}

	cfg, err := nginx.ParseNgxConfigByContent(content)
	if err != nil {
		return fail(batchReplaceReasonConfigUnparseable,
			"The site configuration cannot be parsed: "+err.Error(),
			map[string]string{"error": err.Error()})
	}

	// File-level counts are the safety net for references that live outside
	// server blocks (http-level custom snippets, location/if blocks): the
	// rewrite must only touch the matched server blocks.
	fileCertCount := countDirectivePaths(content, "ssl_certificate", oldCertPath)
	fileKeyCount := countDirectivePaths(content, "ssl_certificate_key", oldKeyPath)

	var matched []matchedCertificateServer
	for index, server := range cfg.Servers {
		certDirectives := directiveNamed(server, "ssl_certificate")
		keyDirectives := directiveNamed(server, "ssl_certificate_key")

		certTokens := make([]string, 0, len(certDirectives))
		for _, directive := range certDirectives {
			certTokens = append(certTokens, unquoteDirectiveValue(trimParams(directive.Params)))
		}
		keyTokens := make([]string, 0, len(keyDirectives))
		for _, directive := range keyDirectives {
			keyTokens = append(keyTokens, unquoteDirectiveValue(trimParams(directive.Params)))
		}

		referencesOld := false
		for _, token := range certTokens {
			if pathsEqualOrSameFile(resolveCertificateDirectivePath(token), oldCertPath) {
				referencesOld = true
				break
			}
		}
		if !referencesOld {
			continue
		}

		if len(certTokens) != 1 || len(keyTokens) != 1 {
			return fail(batchReplaceReasonMultipleDirectives,
				"A relevant server must directly configure exactly one ssl_certificate and one ssl_certificate_key", nil)
		}
		certToken, keyToken := certTokens[0], keyTokens[0]
		if !pathsEqualOrSameFile(resolveCertificateDirectivePath(keyToken), oldKeyPath) {
			resolved := resolveCertificateDirectivePath(keyToken)
			display := keyToken
			if resolved != "" {
				display = resolved
			}
			return fail(batchReplaceReasonPairMismatch,
				"The server pairs the old certificate with a different private key: "+display,
				map[string]string{"path": display})
		}

		var listen []string
		for _, directive := range directiveNamed(server, "listen") {
			listen = append(listen, strings.Fields(trimParams(directive.Params))...)
		}
		matched = append(matched, matchedCertificateServer{
			index:     index,
			listen:    listen,
			names:     serverNameList(server),
			certToken: certToken,
			keyToken:  keyToken,
		})
	}

	if len(matched) == 0 {
		return fail(batchReplaceReasonUnsupportedReference,
			"The certificate is referenced outside a directly configurable server block", nil)
	}
	if fileCertCount != len(matched) || fileKeyCount != len(matched) {
		return fail(batchReplaceReasonUnsupportedReference,
			"The certificate or key is referenced outside the matching server blocks", nil)
	}

	// The new certificate must cover every literal server_name of the matched
	// server blocks, following the same rules as the HTTPS onboarding.
	nameSet := make(map[string]struct{})
	var uncovered []string
	for _, serverMatch := range matched {
		for _, name := range serverMatch.names {
			trimmed := strings.Trim(name, `"'`)
			if trimmed == "" || trimmed == "_" || strings.HasPrefix(trimmed, "~") {
				// Catch-all and regex names cannot be matched against a
				// certificate and are not required to be covered.
				continue
			}
			normalized := normalizeServerName(trimmed)
			if strings.HasSuffix(normalized, ".*") {
				continue
			}
			if _, ok := nameSet[normalized]; ok {
				continue
			}
			nameSet[normalized] = struct{}{}
			if !certificateCoversServerName(leaf, normalized) {
				uncovered = append(uncovered, normalized)
			}
		}
	}
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		return fail(batchReplaceReasonNamesNotCovered,
			"The new certificate does not cover server_name: "+strings.Join(uncovered, ", "),
			map[string]string{"names": strings.Join(uncovered, ", ")})
	}

	certTokenSet := make(map[string]struct{})
	keyTokenSet := make(map[string]struct{})
	for _, serverMatch := range matched {
		certTokenSet[serverMatch.certToken] = struct{}{}
		keyTokenSet[serverMatch.keyToken] = struct{}{}
	}
	replacements := make([]nginx.DirectiveValueReplacement, 0, len(certTokenSet)+len(keyTokenSet))
	for _, token := range sortedKeys(certTokenSet) {
		replacements = append(replacements, nginx.DirectiveValueReplacement{
			Directive: "ssl_certificate", OldValue: token, NewValue: newCertPath,
		})
	}
	for _, token := range sortedKeys(keyTokenSet) {
		replacements = append(replacements, nginx.DirectiveValueReplacement{
			Directive: "ssl_certificate_key", OldValue: token, NewValue: newKeyPath,
		})
	}

	newContent, editCount, err := nginx.RewriteDirectiveValues(content, replacements)
	if err != nil {
		return fail(batchReplaceReasonUnsupportedReference,
			"The certificate directives cannot be rewritten: "+err.Error(), nil)
	}
	if editCount != 2*len(matched) || newContent == content {
		return fail(batchReplaceReasonUnsupportedReference,
			"The certificate directives cannot be rewritten safely", nil)
	}

	servers := make([]CertificateBatchReplaceServer, 0, len(matched))
	for _, serverMatch := range matched {
		names := append([]string(nil), serverMatch.names...)
		listen := append([]string(nil), serverMatch.listen...)
		servers = append(servers, CertificateBatchReplaceServer{
			Index:       serverMatch.index,
			Listen:      listen,
			ServerNames: names,
		})
	}

	result.Selectable = true
	result.Servers = servers
	result.Diff = buildLineDiff(content, newContent)
	result.newContent = newContent
	return result
}

// certificateCoversServerName mirrors nameCoveredByCertificate: a leading
// dot requires both the bare domain and its wildcard form.
func certificateCoversServerName(leaf *x509.Certificate, normalizedName string) bool {
	if strings.HasPrefix(normalizedName, ".") {
		return cert.CertificateCoversIdentifier(leaf, normalizedName[1:]) &&
			cert.CertificateCoversIdentifier(leaf, "*"+normalizedName)
	}
	return cert.CertificateCoversIdentifier(leaf, normalizedName)
}

// countDirectivePaths counts directives whose resolved value points at target.
func countDirectivePaths(content, directive, target string) int {
	values, err := nginx.DirectiveValues(content, directive)
	if err != nil {
		return 0
	}
	count := 0
	for _, value := range values {
		if pathsEqualOrSameFile(resolveCertificateDirectivePath(value), target) {
			count++
		}
	}
	return count
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ApplyCertificateBatchReplace revalidates the preview, then rewrites every
// selected site as one batch. A failure while writing, testing or reloading
// Nginx restores all files of the batch.
func ApplyCertificateBatchReplace(oldCertID, newCertID uint64, newCertHash string,
	selections []CertificateBatchReplaceSelection) (updated []string, err error) {
	if len(selections) == 0 {
		return nil, ErrBatchReplaceNoSitesSelected
	}

	// Drop duplicate rows so one site cannot be written twice in the batch.
	uniqueSelections := selections[:0]
	seen := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		if _, ok := seen[selection.Name]; ok {
			continue
		}
		seen[selection.Name] = struct{}{}
		uniqueSelections = append(uniqueSelections, selection)
	}
	selections = uniqueSelections

	// Rebuild the preview from live state: certificate validity, key match,
	// file contents and eligibility are all rechecked.
	preview, err := PreviewCertificateBatchReplace(oldCertID, newCertID)
	if err != nil {
		return nil, err
	}
	if preview.NewCertificateHash != newCertHash {
		return nil, ErrBatchReplacePreviewStale
	}

	byName := make(map[string]*CertificateBatchReplaceSite, len(preview.Sites))
	for _, sitePreview := range preview.Sites {
		byName[sitePreview.Name] = sitePreview
	}
	for _, selection := range selections {
		sitePreview, ok := byName[selection.Name]
		if !ok || !sitePreview.Selectable {
			reason := "the site no longer references the old certificate"
			if ok && sitePreview.Reason != nil {
				reason = sitePreview.Reason.Message
			}
			return nil, cosy.WrapErrorWithParams(ErrBatchReplaceSiteUnavailable, selection.Name, reason)
		}
		if sitePreview.ContentHash != selection.ContentHash {
			return nil, ErrBatchReplacePreviewStale
		}
	}

	release := config.LockApply()
	defer release()

	// Reopen the pair under the apply lock so coverage checks run against the
	// same bytes that TestAndReload will see.
	pair, err := cert.LoadCertificatePair(preview.NewCertificatePath, preview.NewCertificateKeyPath)
	if err != nil {
		return nil, cosy.WrapErrorWithParams(ErrBatchReplaceCertificateUnusable, err.Error())
	}

	tx := &config.FileTransaction{}
	for _, selection := range selections {
		path, errPath := ResolveAvailablePath(selection.Name)
		if errPath != nil {
			return nil, errPath
		}

		// Re-read and re-analyze under the apply lock to close the race
		// between preview validation and the write.
		contentBytes, errRead := nginx.ReadFile(path)
		if errRead != nil {
			return nil, errRead
		}
		if sha256Hex(contentBytes) != selection.ContentHash {
			return nil, ErrBatchReplacePreviewStale
		}
		live := analyzeBatchReplaceSite(selection.Name, path, string(contentBytes),
			preview.OldCertificatePath, preview.OldCertificateKeyPath,
			preview.NewCertificatePath, preview.NewCertificateKeyPath, pair.Leaf)
		if !live.Selectable {
			reason := ""
			if live.Reason != nil {
				reason = live.Reason.Message
			}
			return nil, cosy.WrapErrorWithParams(ErrBatchReplaceSiteUnavailable, selection.Name, reason)
		}

		if err = config.ValidateConfigFile(path, live.newContent); err != nil {
			return nil, config.RollbackError(err, tx.Rollback)
		}
		if err = config.CheckAndCreateHistory(path, live.newContent); err != nil {
			return nil, config.RollbackError(err, tx.Rollback)
		}
		if err = tx.Write(path, []byte(live.newContent), 0o644); err != nil {
			return nil, config.RollbackError(err, tx.Rollback)
		}
		updated = append(updated, selection.Name)
	}

	if err = tx.TestAndReload(); err != nil {
		return nil, err
	}

	return updated, nil
}

// buildLineDiff produces a compact line diff with two lines of context around
// every changed region.
func buildLineDiff(before, after string) []CertificateBatchReplaceDiffLine {
	oldLines := strings.Split(strings.TrimSuffix(before, "\n"), "\n")
	newLines := strings.Split(strings.TrimSuffix(after, "\n"), "\n")

	type op struct {
		kind string // "equal", "remove", "add"
		old  int    // 1-based, 0 when absent
		new  int
		text string
	}

	// Longest-common-subsequence table. Site configuration files are small.
	dp := make([][]int, len(oldLines)+1)
	for i := range dp {
		dp[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var ops []op
	i, j := 0, 0
	oldNo, newNo := 0, 0
	for i < len(oldLines) || j < len(newLines) {
		switch {
		case i < len(oldLines) && j < len(newLines) && oldLines[i] == newLines[j]:
			oldNo++
			newNo++
			ops = append(ops, op{kind: "equal", old: oldNo, new: newNo, text: oldLines[i]})
			i++
			j++
		case j >= len(newLines) || (i < len(oldLines) && dp[i+1][j] >= dp[i][j+1]):
			oldNo++
			ops = append(ops, op{kind: "remove", old: oldNo, text: oldLines[i]})
			i++
		default:
			newNo++
			ops = append(ops, op{kind: "add", new: newNo, text: newLines[j]})
			j++
		}
	}

	const context = 2
	changed := make([]int, 0)
	for k, operation := range ops {
		if operation.kind != "equal" {
			changed = append(changed, k)
		}
	}

	type window struct{ start, end int }
	var windows []window
	for _, k := range changed {
		start := k - context
		if start < 0 {
			start = 0
		}
		end := k + context + 1
		if end > len(ops) {
			end = len(ops)
		}
		if len(windows) > 0 && start <= windows[len(windows)-1].end {
			if end > windows[len(windows)-1].end {
				windows[len(windows)-1].end = end
			}
		} else {
			windows = append(windows, window{start: start, end: end})
		}
	}

	lines := make([]CertificateBatchReplaceDiffLine, 0)
	for wi, win := range windows {
		if wi > 0 || win.start > 0 {
			lines = append(lines, CertificateBatchReplaceDiffLine{Type: "spacer", Text: "..."})
		}
		for k := win.start; k < win.end; k++ {
			operation := ops[k]
			diffType := operation.kind
			if diffType == "equal" {
				diffType = "context"
			}
			lines = append(lines, CertificateBatchReplaceDiffLine{
				Type:  diffType,
				Text:  operation.text,
				OldNo: operation.old,
				NewNo: operation.new,
			})
		}
	}
	return lines
}
