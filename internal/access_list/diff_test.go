package access_list

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiffLinesReplacement(t *testing.T) {
	before := "server {\n    listen 80;\n    allow 1.1.1.1;\n    deny all;\n}\n"
	after := "server {\n    listen 80;\n    include nginx-ui/access/x.conf;\n}\n"

	lines := diffLines(before, after)
	var kinds []string
	var removed, added []string
	for _, line := range lines {
		kinds = append(kinds, line.Kind)
		switch line.Kind {
		case DiffRemove:
			removed = append(removed, line.Text)
		case DiffAdd:
			added = append(added, line.Text)
		}
	}

	assert.Contains(t, kinds, DiffRemove)
	assert.Contains(t, kinds, DiffAdd)
	assert.Contains(t, removed, "    allow 1.1.1.1;")
	assert.Contains(t, removed, "    deny all;")
	assert.Contains(t, added, "    include nginx-ui/access/x.conf;")
}

func TestDiffLinesIdentical(t *testing.T) {
	content := "server {\n    listen 80;\n}\n"
	lines := diffLines(content, content)
	for _, line := range lines {
		assert.NotEqual(t, DiffRemove, line.Kind)
		assert.NotEqual(t, DiffAdd, line.Kind)
	}
}

func TestDiffLinesHunks(t *testing.T) {
	before := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\nq\nr\ns\nt\nu\nv\nw\nx\ny\nz\n"
	after := "a\nB\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\nq\nr\ns\nt\nu\nv\nw\nx\ny\nZ\n"

	lines := diffLines(before, after)
	hunks := 0
	for _, line := range lines {
		if line.Kind == DiffHunk {
			hunks++
		}
	}
	assert.Equal(t, 1, hunks)
}
