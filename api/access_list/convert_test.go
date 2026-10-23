package access_list

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/0xJacky/Nginx-UI/internal/testdb"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/query"
	"github.com/0xJacky/Nginx-UI/settings"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const convertSiteName = "example.com"

var convertSiteContent = `server {
    listen 80;
    server_name example.com;

    # office network
    allow 10.0.0.0/8;
    deny 203.0.113.5;

    root /var/www/html;
}
`

type convertRouterEnv struct {
	router *gin.Engine
	db     *gorm.DB
	dir    string
}

func newConvertRouter(t *testing.T) *convertRouterEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(testdb.DSN(t)), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.AccessList{},
		&model.Site{},
		&model.Namespace{},
		&model.ConfigBackup{},
	))
	model.Use(db)
	query.SetDefault(db)

	dir := t.TempDir()
	previous := settings.NginxSettings.ConfigDir
	settings.NginxSettings.ConfigDir = dir
	t.Cleanup(func() {
		settings.NginxSettings.ConfigDir = previous
		model.Use(nil)
		site.WaitForSync()
	})

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sites-available"), 0o755))

	router := gin.New()
	router.POST("sites/:name/access_conversion/preview", PreviewSiteAccessConversion)
	router.POST("sites/:name/access_conversion/commit", CommitSiteAccessConversion)

	return &convertRouterEnv{router: router, db: db, dir: dir}
}

func (env *convertRouterEnv) writeSite(t *testing.T, content string) string {
	t.Helper()
	path, err := site.ResolveAvailablePath(convertSiteName)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func (env *convertRouterEnv) listPath(slug string) string {
	return filepath.Join(env.dir, "nginx-ui", "access", slug+".conf")
}

func (env *convertRouterEnv) post(t *testing.T, action string, body gin.H) *map[string]any {
	t.Helper()
	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/"+action, body)
	if w.Code != http.StatusOK {
		t.Fatalf("%s expected 200, got %d: %s", action, w.Code, w.Body.String())
	}
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return &resp
}

func TestPreviewSiteAccessConversion(t *testing.T) {
	env := newConvertRouter(t)
	env.writeSite(t, convertSiteContent)

	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/preview", gin.H{
		"server": 0,
		"name":   "Site Rules",
		"slug":   "site-rules",
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Token    string             `json:"token"`
		Rules    []model.AccessRule `json:"rules"`
		Fallback string             `json:"fallback"`
		Diff     []struct {
			Kind string `json:"kind"`
			Text string `json:"text"`
		} `json:"diff"`
		ServerName string `json:"server_name"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, model.AccessFallbackAllow, resp.Fallback)
	assert.Equal(t, "example.com", resp.ServerName)
	require.Len(t, resp.Rules, 2)
	assert.Equal(t, "10.0.0.0/8", resp.Rules[0].Value)
	assert.Equal(t, "office network", resp.Rules[0].Note)
	assert.Equal(t, model.AccessRuleDeny, resp.Rules[1].Type)

	kinds := map[string]bool{}
	for _, line := range resp.Diff {
		kinds[line.Kind] = true
	}
	assert.True(t, kinds["add"] && kinds["remove"])

	// Preview writes nothing.
	_, err := os.Stat(env.listPath("site-rules"))
	assert.True(t, os.IsNotExist(err))
}

func TestPreviewRejectsBlockProblems(t *testing.T) {
	env := newConvertRouter(t)

	cases := []struct {
		name    string
		content string
		body    gin.H
		code    int32
	}{
		{
			name: "include in block",
			content: `server {
    listen 80;
    include nginx-ui/access/old.conf;
    allow 1.1.1.1;
}
`,
			body: gin.H{"server": 0, "name": "X", "slug": "x"},
			code: 40018,
		},
		{
			name: "no rules in server",
			content: `server {
    listen 80;
    root /var/www;
}
`,
			body: gin.H{"server": 0, "name": "X", "slug": "x"},
			code: 40019,
		},
		{
			name: "no rules in location",
			content: `server {
    listen 80;
    location / {
        return 200;
    }
}
`,
			body: gin.H{"server": 0, "location": 0, "name": "X", "slug": "x"},
			code: 40019,
		},
		{
			name: "bad rule",
			content: `server {
    listen 80;
    deny not-an-ip;
}
`,
			body: gin.H{"server": 0, "name": "X", "slug": "x"},
			code: 40020,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env.writeSite(t, tc.content)
			w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/preview", tc.body)
			assert.NotEqual(t, http.StatusOK, w.Code)
			var resp struct {
				Code int32 `json:"code"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tc.code, resp.Code)
		})
	}
}

func TestPreviewRejectsIneligibleSites(t *testing.T) {
	env := newConvertRouter(t)
	path := env.writeSite(t, convertSiteContent)

	namespaceLocal := &model.Namespace{Name: "local", DeployMode: model.DeployModeLocal}
	namespaceRemote := &model.Namespace{Name: "remote", DeployMode: model.DeployModeRemote}
	require.NoError(t, env.db.Create(namespaceLocal).Error)
	require.NoError(t, env.db.Create(namespaceRemote).Error)

	cases := []struct {
		name string
		site model.Site
		code int32
	}{
		{
			name: "managed by ingress",
			site: model.Site{Path: path, ManagedBy: "ingress:web"},
			code: 40021,
		},
		{
			name: "site sync target",
			site: model.Site{Path: path, SyncNodeIDs: []uint64{9}},
			code: 40022,
		},
		{
			name: "namespace sync target",
			site: model.Site{Path: path, NamespaceID: namespaceLocal.ID, SyncNodeIDs: nil},
			code: 40022,
		},
		{
			name: "remote namespace",
			site: model.Site{Path: path, NamespaceID: namespaceRemote.ID},
			code: 40023,
		},
	}
	body := gin.H{"server": 0, "name": "X", "slug": "x"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The local namespace gains a sync node only for this case.
			localSync := tc.name == "namespace sync target"
			namespaceLocal.SyncNodeIds = map[bool][]uint64{true: {7}}[localSync]
			require.NoError(t, env.db.Save(namespaceLocal).Error)

			require.NoError(t, env.db.Create(&tc.site).Error)
			w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/preview", body)
			assert.NotEqual(t, http.StatusOK, w.Code)
			var resp struct {
				Code int32 `json:"code"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tc.code, resp.Code, w.Body.String())
			require.NoError(t, env.db.Unscoped().Delete(&tc.site).Error)
			namespaceLocal.SyncNodeIds = nil
			require.NoError(t, env.db.Save(namespaceLocal).Error)
		})
	}
}

func TestPreviewRejectsOccupiedTargets(t *testing.T) {
	env := newConvertRouter(t)
	env.writeSite(t, convertSiteContent)

	// The slug already belongs to a stored list.
	require.NoError(t, env.db.Create(&model.AccessList{
		Name: "Existing", Slug: "site-rules", Fallback: model.AccessFallbackDeny,
	}).Error)
	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/preview", gin.H{
		"server": 0, "name": "Site Rules", "slug": "site-rules",
	})
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "40003")
	require.NoError(t, env.db.Unscoped().Where("slug = ?", "site-rules").Delete(&model.AccessList{}).Error)

	// The file exists without an access list row.
	require.NoError(t, os.MkdirAll(filepath.Dir(env.listPath("orphan")), 0o755))
	require.NoError(t, os.WriteFile(env.listPath("orphan"), []byte("allow 1.2.3.4;\n"), 0o644))
	w = postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/preview", gin.H{
		"server": 0, "name": "Orphan", "slug": "orphan",
	})
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "40025")
}

func TestCommitSiteAccessConversion(t *testing.T) {
	env := newConvertRouter(t)
	path := env.writeSite(t, convertSiteContent)

	resp := env.post(t, "preview", gin.H{"server": 0, "name": "Site Rules", "slug": "site-rules"})
	token, _ := (*resp)["token"].(string)
	require.NotEmpty(t, token)

	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/commit", gin.H{
		"server": 0, "name": "Site Rules", "slug": "site-rules", "token": token,
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var result struct {
		List struct {
			model.AccessList
			Warnings []string `json:"warnings"`
		} `json:"list"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, "site-rules", result.List.Slug)
	assert.Equal(t, model.AccessFallbackAllow, result.List.Fallback)
	require.Len(t, result.List.Rules, 2)
	assert.NotZero(t, result.List.ID)

	// The site file now references the list and no longer carries the rules.
	updated, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(updated), "include nginx-ui/access/site-rules.conf;")
	assert.NotContains(t, string(updated), "10.0.0.0/8")
	assert.Contains(t, string(updated), "server_name example.com;")
	assert.Contains(t, string(updated), "root /var/www/html;")

	// The rendered list exists and ends with allow all.
	rendered, err := os.ReadFile(env.listPath("site-rules"))
	require.NoError(t, err)
	assert.Contains(t, string(rendered), "allow 10.0.0.0/8; # office network")
	assert.Contains(t, string(rendered), "deny 203.0.113.5;")
	assert.True(t, strings.HasSuffix(string(rendered), "\n"))
	assert.Contains(t, string(rendered), "allow all;")

	// The site stays disabled: no sites-enabled entry was created.
	enabledPath, err := site.ResolveEnabledPath(convertSiteName)
	require.NoError(t, err)
	_, err = os.Stat(enabledPath)
	assert.True(t, os.IsNotExist(err))

	// Save starts a background sync goroutine that still reads global paths;
	// wait for it so the cleanup that swaps NginxSettings cannot race it.
	site.WaitForSync()
}

func TestCommitRejectsStalePreview(t *testing.T) {
	env := newConvertRouter(t)
	env.writeSite(t, convertSiteContent)

	resp := env.post(t, "preview", gin.H{"server": 0, "name": "Site Rules", "slug": "site-rules"})
	token, _ := (*resp)["token"].(string)

	// The source file changes after the preview.
	env.writeSite(t, convertSiteContent+"# changed after preview\n")

	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/commit", gin.H{
		"server": 0, "name": "Site Rules", "slug": "site-rules", "token": token,
	})
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "40024")

	_, err := os.Stat(env.listPath("site-rules"))
	assert.True(t, os.IsNotExist(err))
}

func TestCommitRollsBackWhenSiteSaveFails(t *testing.T) {
	env := newConvertRouter(t)
	path := env.writeSite(t, convertSiteContent)

	resp := env.post(t, "preview", gin.H{"server": 0, "name": "Site Rules", "slug": "site-rules"})
	token, _ := (*resp)["token"].(string)

	// Make the site file read-only after the preview, so site.Save cannot put
	// the rewritten configuration in place.
	require.NoError(t, os.Chmod(path, 0o444))
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/commit", gin.H{
		"server": 0, "name": "Site Rules", "slug": "site-rules", "token": token,
	})
	assert.NotEqual(t, http.StatusOK, w.Code)

	// Nothing converted: original site content, no list file and no database row.
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, convertSiteContent, string(raw))
	_, err = os.Stat(env.listPath("site-rules"))
	assert.True(t, os.IsNotExist(err))
	var count int64
	require.NoError(t, env.db.Model(&model.AccessList{}).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func TestCommitRollsBackWhenDatabaseFails(t *testing.T) {
	env := newConvertRouter(t)
	path := env.writeSite(t, convertSiteContent)

	resp := env.post(t, "preview", gin.H{"server": 0, "name": "Site Rules", "slug": "site-rules"})
	token, _ := (*resp)["token"].(string)

	// Point the model database at an empty database: saving the site still
	// works through query, but creating the access list row fails.
	badDB, err := gorm.Open(sqlite.Open(testdb.DSN(t)), &gorm.Config{})
	require.NoError(t, err)
	model.Use(badDB)
	t.Cleanup(func() { model.Use(env.db) })

	w := postJSON(env.router, "/sites/"+convertSiteName+"/access_conversion/commit", gin.H{
		"server": 0, "name": "Site Rules", "slug": "site-rules", "token": token,
	})
	assert.NotEqual(t, http.StatusOK, w.Code)
	site.WaitForSync()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, convertSiteContent, string(raw))
	_, err = os.Stat(env.listPath("site-rules"))
	assert.True(t, os.IsNotExist(err))
	var count int64
	require.NoError(t, env.db.Model(&model.AccessList{}).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}
