package access_list

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/0xJacky/Nginx-UI/model"
	"github.com/uozi-tech/cosy"
)

// ConvertTarget selects the server block or one of its direct locations whose
// allow and deny rules become a new access list.
type ConvertTarget struct {
	Server   int
	Location *int
}

// DiffLine is one line of the configuration preview.
type DiffLine struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Diff line kinds.
const (
	DiffContext = "context"
	DiffAdd     = "add"
	DiffRemove  = "remove"
	DiffHunk    = "hunk"
)

// ConvertPlan is the computed result of a conversion preview. The rules keep
// their order, the list ends with "allow all" so requests no rule matched
// still pass, and the site content only exchanges the rule directives for an
// include of the rendered list.
type ConvertPlan struct {
	List         *model.AccessList
	Rules        []model.AccessRule
	ListContent  string
	Content      string
	Diff         []DiffLine
	ServerName   string
	LocationPath string
}

func blockLabel(serverIdx int, location *int, block *statement) string {
	if location != nil {
		return "location " + locationPath(block) + " of server " + strconv.Itoa(serverIdx+1)
	}
	return "server " + strconv.Itoa(serverIdx+1)
}

// locateConvertBlock parses content and returns the selected server block, the
// block to convert (the server itself or one of its direct locations) and its
// label.
func locateConvertBlock(content string, target ConvertTarget) (*statement, *statement, string, error) {
	roots, err := parseStatements(content)
	if err != nil {
		return nil, nil, "", cosy.WrapErrorWithParams(ErrConvertParse, err.Error())
	}
	servers := serverBlocks(roots)
	if target.Server < 0 || target.Server >= len(servers) {
		return nil, nil, "", cosy.WrapErrorWithParams(ErrServerNotFound, strconv.Itoa(target.Server+1))
	}
	server := servers[target.Server]
	if target.Location == nil {
		return server, server, blockLabel(target.Server, nil, server), nil
	}
	locations := locationBlocks(server)
	if *target.Location < 0 || *target.Location >= len(locations) {
		return nil, nil, "", cosy.WrapErrorWithParams(ErrLocationNotFound, strconv.Itoa(*target.Location+1), strconv.Itoa(target.Server+1))
	}
	block := locations[*target.Location]
	return server, block, blockLabel(target.Server, target.Location, block), nil
}

// ruleNote turns the comment lines directly above a rule into the single line
// stored as the rule note.
func ruleNote(comments []comment) string {
	parts := make([]string, 0, len(comments))
	for _, c := range comments {
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(c.Text), "#"))
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, " ")
}

// extractConvertRules collects the allow and deny directives directly inside
// block in their configuration order, turning leading comments into notes. A
// block with a direct include cannot be converted safely, because the include
// may pull in further access directives.
func extractConvertRules(block *statement, label string) ([]model.AccessRule, []*statement, error) {
	var ruleStmts []*statement
	for _, st := range block.Children {
		switch st.Name {
		case "include":
			return nil, nil, cosy.WrapErrorWithParams(ErrConvertBlockHasInclude, label)
		case "allow", "deny":
			ruleStmts = append(ruleStmts, st)
		}
	}
	if len(ruleStmts) == 0 {
		return nil, nil, cosy.WrapErrorWithParams(ErrConvertNoRules, label)
	}

	rules := make([]model.AccessRule, 0, len(ruleStmts))
	for i, st := range ruleStmts {
		if len(st.Args) != 1 || !ValidAddress(st.Args[0]) {
			raw := strings.TrimSpace(st.Name + " " + strings.Join(st.Args, " "))
			return nil, nil, cosy.WrapErrorWithParams(ErrConvertInvalidRule, strconv.Itoa(i+1), label, raw)
		}
		rules = append(rules, model.AccessRule{
			Type:  st.Name,
			Value: st.Args[0],
			Note:  ruleNote(st.Comments),
		})
	}
	return rules, ruleStmts, nil
}

func lineStart(src string, offset int) int {
	return strings.LastIndexByte(src[:offset], '\n') + 1
}

// replaceRulesWithInclude removes the rule statements, together with their
// leading comments, and puts a single include directive where the first rule
// stood, so the directive order within the block is preserved.
func replaceRulesWithInclude(src string, block *statement, ruleStmts []*statement, slug string) string {
	spans := make([]span, 0, len(ruleStmts)*2)
	for _, st := range ruleStmts {
		for _, c := range st.Comments {
			spans = append(spans, span{start: c.Start, end: c.End})
		}
		spans = append(spans, span{start: st.Start, end: st.End})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	insertAt := lineStart(src, spans[0].start)
	inline := strings.TrimSpace(src[insertAt:spans[0].start]) != ""
	if inline {
		// A rule sharing its line with another directive is replaced in place
		// rather than at the start of that line.
		insertAt = spans[0].start
	}
	updated := removeSpans(src, spans)

	include := "include " + IncludePath(slug) + ";"
	if inline {
		// A rule shared its line with another directive; keep that line intact.
		return updated[:insertAt] + include + updated[insertAt:]
	}
	indent, ok := lineIndent(src, ruleStmts[0].Start)
	if !ok {
		indent = childIndent(src, block, false)
	}
	line := indent + include + "\n"
	return updated[:insertAt] + line + updated[insertAt:]
}

// PlanConversion extracts the rules of the selected block and computes the new
// access list, its rendered file and the rewritten site configuration without
// touching the disk or the database.
func PlanConversion(content string, target ConvertTarget, listName, slug string) (*ConvertPlan, error) {
	server, block, label, err := locateConvertBlock(content, target)
	if err != nil {
		return nil, err
	}
	rules, ruleStmts, err := extractConvertRules(block, label)
	if err != nil {
		return nil, err
	}

	list := &model.AccessList{
		Name:     strings.TrimSpace(listName),
		Slug:     strings.TrimSpace(slug),
		Fallback: model.AccessFallbackAllow,
		Rules:    rules,
	}
	// Slug uniqueness is checked by the caller against the stored lists; the
	// rest of the validation runs here.
	if err = Validate(list, nil); err != nil {
		return nil, err
	}
	rendered, err := Render(list, nil)
	if err != nil {
		return nil, err
	}

	updated := replaceRulesWithInclude(content, block, ruleStmts, list.Slug)
	if err = assertConverted(updated, target, list.Slug); err != nil {
		return nil, err
	}

	plan := &ConvertPlan{
		List:        list,
		Rules:       rules,
		ListContent: rendered,
		Content:     updated,
		Diff:        diffLines(content, updated),
		ServerName:  serverName(server.Children),
	}
	if target.Location != nil {
		plan.LocationPath = locationPath(block)
	}
	return plan, nil
}

// assertConverted guarantees the rewritten block references exactly the new
// list and no longer carries allow or deny rules.
func assertConverted(content string, target ConvertTarget, slug string) error {
	_, block, _, err := locateConvertBlock(content, target)
	if err != nil {
		return err
	}
	access := inspectStatements(block.Children)
	if len(access.slugs) != 1 || access.slugs[0] != slug || access.rules != 0 {
		return ErrConfigSyntax
	}
	return nil
}

// ---- line diff -------------------------------------------------------------

// diffLines computes a line based diff with a few context lines around every
// change.
func diffLines(before, after string) []DiffLine {
	a := splitConfigLines(before)
	b := splitConfigLines(after)
	ops := lcsOps(a, b)

	const context = 3
	var changeIdx []int
	for i, op := range ops {
		if op.kind != DiffContext {
			changeIdx = append(changeIdx, i)
		}
	}
	if len(changeIdx) == 0 {
		lines := make([]DiffLine, 0, len(ops))
		for _, op := range ops {
			lines = append(lines, DiffLine{Kind: DiffContext, Text: op.text})
		}
		return lines
	}

	lines := make([]DiffLine, 0, len(ops))
	windowStart := 0
	windowEnd := -1
	for _, idx := range changeIdx {
		start := idx - context
		if start < 0 {
			start = 0
		}
		end := idx + context
		if end >= len(ops) {
			end = len(ops) - 1
		}
		if windowEnd < 0 {
			windowStart, windowEnd = start, end
			continue
		}
		if start <= windowEnd+1 {
			if end > windowEnd {
				windowEnd = end
			}
			continue
		}
		appendDiffWindow(&lines, ops, windowStart, windowEnd)
		lines = append(lines, DiffLine{Kind: DiffHunk, Text: "@@"})
		windowStart, windowEnd = start, end
	}
	appendDiffWindow(&lines, ops, windowStart, windowEnd)
	return lines
}

type diffOp struct {
	kind string
	text string
}

func appendDiffWindow(lines *[]DiffLine, ops []diffOp, start, end int) {
	for i := start; i <= end; i++ {
		*lines = append(*lines, DiffLine{Kind: ops[i].kind, Text: ops[i].text})
	}
}

func splitConfigLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// lcsOps aligns a and b with a longest common subsequence and tags every line
// as context, removed or added.
func lcsOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	ops := make([]diffOp, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{DiffContext, a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, diffOp{DiffRemove, a[i]})
			i++
		default:
			ops = append(ops, diffOp{DiffAdd, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{DiffRemove, a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{DiffAdd, b[j]})
	}
	return ops
}

// ---- change token ----------------------------------------------------------

// conversionFingerprint is the canonical state a preview is valid for.
type conversionFingerprint struct {
	Name     string `json:"name"`
	Content  string `json:"content"`
	Server   int    `json:"server"`
	Location *int   `json:"location,omitempty"`
	ListName string `json:"list_name"`
	Slug     string `json:"slug"`
}

// ConversionToken binds a commit to the exact site content and conversion
// inputs of a preview. The same content later produces the same token, so the
// commit can reject a conversion whose source configuration changed.
func ConversionToken(siteName, content string, target ConvertTarget, listName, slug string) string {
	payload, _ := json.Marshal(conversionFingerprint{
		Name:     siteName,
		Content:  content,
		Server:   target.Server,
		Location: target.Location,
		ListName: listName,
		Slug:     slug,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
