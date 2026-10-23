package access_list

import (
	"strings"
	"testing"

	"github.com/0xJacky/Nginx-UI/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(v int) *int { return &v }

func TestPlanConversionServerRules(t *testing.T) {
	content := `server {
    listen 80;
    server_name example.com;

    # office network
    allow 10.0.0.0/8;
    # temporary ban
    # keep for a week
    deny 203.0.113.5;
    allow all;

    root /var/www/html;
}
`
	plan, err := PlanConversion(content, ConvertTarget{Server: 0}, "Office Access", "office-access")
	require.NoError(t, err)

	require.Len(t, plan.Rules, 3)
	assert.Equal(t, model.AccessRuleAllow, plan.Rules[0].Type)
	assert.Equal(t, "10.0.0.0/8", plan.Rules[0].Value)
	assert.Equal(t, "office network", plan.Rules[0].Note)
	assert.Equal(t, model.AccessRuleDeny, plan.Rules[1].Type)
	assert.Equal(t, "203.0.113.5", plan.Rules[1].Value)
	assert.Equal(t, "temporary ban keep for a week", plan.Rules[1].Note)
	assert.Equal(t, "all", plan.Rules[2].Value)
	assert.Equal(t, model.AccessFallbackAllow, plan.List.Fallback)
	assert.Equal(t, "example.com", plan.ServerName)
	assert.Empty(t, plan.LocationPath)

	// The rendered file keeps rule order, carries notes and ends with allow all.
	assert.Contains(t, plan.ListContent, "allow 10.0.0.0/8; # office network")
	assert.Contains(t, plan.ListContent, "deny 203.0.113.5; # temporary ban keep for a week")
	assert.True(t, strings.HasSuffix(strings.TrimSpace(plan.ListContent), "allow all;"))

	// The site content exchanges the rules for one include and keeps the rest.
	assert.Contains(t, plan.Content, "include "+IncludePath("office-access")+";")
	assert.NotContains(t, plan.Content, "allow 10.0.0.0/8")
	assert.NotContains(t, plan.Content, "# office network")
	assert.Contains(t, plan.Content, "listen 80;")
	assert.Contains(t, plan.Content, "server_name example.com;")
	assert.Contains(t, plan.Content, "root /var/www/html;")
	assert.Equal(t, 1, strings.Count(plan.Content, IncludePath("office-access")))

	// The diff describes the removed rules and the added include.
	var removed, added int
	for _, line := range plan.Diff {
		switch line.Kind {
		case DiffRemove:
			removed++
		case DiffAdd:
			added++
		}
	}
	assert.Greater(t, removed, 0)
	assert.Greater(t, added, 0)
}

func TestPlanConversionLocationRules(t *testing.T) {
	content := `server {
    listen 443 ssl;
    server_name app.example.com;

    location /admin/ {
        # only the VPN may reach the admin panel
        allow 198.51.100.0/24;
        deny all;
        proxy_pass http://backend;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
`
	plan, err := PlanConversion(content, ConvertTarget{Server: 0, Location: intPtr(0)}, "Admin", "admin")
	require.NoError(t, err)

	assert.Equal(t, "/admin/", plan.LocationPath)
	assert.Equal(t, "app.example.com", plan.ServerName)
	require.Len(t, plan.Rules, 2)
	assert.Equal(t, "only the VPN may reach the admin panel", plan.Rules[0].Note)

	assert.Contains(t, plan.Content, "location /admin/ {")
	assert.Contains(t, plan.Content, "include "+IncludePath("admin")+";")
	assert.Contains(t, plan.Content, "proxy_pass http://backend;")
	assert.NotContains(t, plan.Content, "198.51.100.0/24")
	// The second location is untouched.
	assert.Contains(t, plan.Content, "try_files $uri $uri/ =404;")
}

func TestPlanConversionRejectsInclude(t *testing.T) {
	content := `server {
    listen 80;
    include nginx-ui/access/old.conf;
    allow 1.1.1.1;
}
`
	_, err := PlanConversion(content, ConvertTarget{Server: 0}, "X", "x")
	assertErrCode(t, err, ErrConvertBlockHasInclude)
}

func TestPlanConversionRejectsNestedLocationRulesAtServerLevel(t *testing.T) {
	content := `server {
    listen 80;
    location / {
        allow 1.1.1.1;
    }
}
`
	_, err := PlanConversion(content, ConvertTarget{Server: 0}, "X", "x")
	assertErrCode(t, err, ErrConvertNoRules)
}

func TestPlanConversionRejectsInvalidRules(t *testing.T) {
	cases := map[string]string{
		"missing argument": "server {\n listen 80;\n allow;\n}\n",
		"bad address":      "server {\n listen 80;\n deny not-an-ip;\n}\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := PlanConversion(content, ConvertTarget{Server: 0}, "X", "x")
			assertErrCode(t, err, ErrConvertInvalidRule)
		})
	}
}

func TestPlanConversionRejectsUnknownBlocks(t *testing.T) {
	content := "server {\n listen 80;\n allow 1.1.1.1;\n}\n"

	_, err := PlanConversion(content, ConvertTarget{Server: 2}, "X", "x")
	assertErrCode(t, err, ErrServerNotFound)

	_, err = PlanConversion(content, ConvertTarget{Server: 0, Location: intPtr(1)}, "X", "x")
	assertErrCode(t, err, ErrLocationNotFound)
}

func TestPlanConversionRejectsInvalidNameAndSlug(t *testing.T) {
	content := "server {\n listen 80;\n allow 1.1.1.1;\n}\n"

	_, err := PlanConversion(content, ConvertTarget{Server: 0}, "", "x")
	assertErrCode(t, err, ErrInvalidName)

	_, err = PlanConversion(content, ConvertTarget{Server: 0}, "X", "Bad Slug!")
	assertErrCode(t, err, ErrInvalidSlug)
}

func TestPlanConversionSharedLineRule(t *testing.T) {
	content := "server { listen 80; allow 1.1.1.1; root /srv/www; }\n"
	plan, err := PlanConversion(content, ConvertTarget{Server: 0}, "X", "x")
	require.NoError(t, err)

	assert.Contains(t, plan.Content, "listen 80;")
	assert.Contains(t, plan.Content, "include "+IncludePath("x")+";")
	assert.Contains(t, plan.Content, "root /srv/www;")
	assert.NotContains(t, plan.Content, "allow 1.1.1.1")
}

func TestConversionTokenDetectsChanges(t *testing.T) {
	content := "server {\n listen 80;\n allow 1.1.1.1;\n}\n"
	target := ConvertTarget{Server: 0}

	original := ConversionToken("site.conf", content, target, "X", "x")
	assert.Equal(t, original, ConversionToken("site.conf", content, target, "X", "x"))
	assert.NotEqual(t, original, ConversionToken("site.conf", content+"\n", target, "X", "x"))
	assert.NotEqual(t, original, ConversionToken("other.conf", content, target, "X", "x"))
	assert.NotEqual(t, original, ConversionToken("site.conf", content, target, "Y", "x"))
	assert.NotEqual(t, original, ConversionToken("site.conf", content, target, "X", "y"))
}
