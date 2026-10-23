package access_list

import (
	"errors"
	"net/http"
	"os"
	"strings"

	internalaccess "github.com/0xJacky/Nginx-UI/internal/access_list"
	"github.com/0xJacky/Nginx-UI/internal/config"
	"github.com/0xJacky/Nginx-UI/internal/helper"
	"github.com/0xJacky/Nginx-UI/internal/nginx"
	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/0xJacky/Nginx-UI/query"
	"github.com/gin-gonic/gin"
	"github.com/uozi-tech/cosy"
	"gorm.io/gorm"
)

// accessConversionRequest selects the block to convert and names the new
// access list. Commit additionally carries the preview token.
type accessConversionRequest struct {
	Server   int    `json:"server"`
	Location *int   `json:"location"`
	Name     string `json:"name" binding:"required,max=100"`
	Slug     string `json:"slug" binding:"required"`
	Token    string `json:"token"`
}

func (r accessConversionRequest) target() internalaccess.ConvertTarget {
	return internalaccess.ConvertTarget{Server: r.Server, Location: r.Location}
}

type accessConversionResponse struct {
	Token        string                    `json:"token"`
	Server       int                       `json:"server"`
	Location     *int                      `json:"location,omitempty"`
	ServerName   string                    `json:"server_name"`
	LocationPath string                    `json:"location_path,omitempty"`
	Name         string                    `json:"name"`
	Slug         string                    `json:"slug"`
	Fallback     string                    `json:"fallback"`
	Rules        []model.AccessRule        `json:"rules"`
	ListContent  string                    `json:"list_content"`
	Content      string                    `json:"content"`
	Diff         []internalaccess.DiffLine `json:"diff"`
}

func isInvalidConversionSiteName(name string) bool {
	return name == "" || name == "." ||
		strings.ContainsAny(name, `/\`) || strings.Contains(name, "..")
}

// loadConvertibleSite resolves a saved site and rejects every site the
// conversion must not touch: ingress managed sites, sites with their own sync
// targets, and sites owned by a remote namespace or a namespace with sync
// targets. A site without a database row is a plain local site.
func loadConvertibleSite(name string) (record *model.Site, path string, err error) {
	path, err = site.ResolveAvailablePath(name)
	if err != nil {
		return
	}

	s := query.Site
	record, queryErr := s.Where(s.Path.Eq(path)).Preload(s.Namespace).First()
	if queryErr != nil {
		if !errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return nil, "", queryErr
		}
		record = &model.Site{}
	}

	if record.ManagedBy != "" {
		manager := strings.TrimPrefix(record.ManagedBy, "ingress:")
		err = cosy.WrapErrorWithParams(internalaccess.ErrConvertSiteManaged, manager)
		return
	}
	if len(record.SyncNodeIDs) > 0 {
		err = internalaccess.ErrConvertSyncTarget
		return
	}
	if record.Namespace != nil {
		if record.Namespace.IsRemoteDeploy() {
			err = cosy.WrapErrorWithParams(internalaccess.ErrConvertRemoteNamespace, record.Namespace.Name)
			return
		}
		if len(record.Namespace.SyncNodeIds) > 0 {
			err = internalaccess.ErrConvertSyncTarget
			return
		}
	}
	return record, path, nil
}

func readSiteForConversion(path string) (string, error) {
	raw, err := nginx.ReadFile(path)
	if err != nil {
		return "", cosy.WrapErrorWithParams(internalaccess.ErrConvertSiteRead, err.Error())
	}
	return string(raw), nil
}

// prepareConversion runs every check that preview and commit share.
func prepareConversion(content string, req accessConversionRequest) (*internalaccess.ConvertPlan, error) {
	plan, err := internalaccess.PlanConversion(content, req.target(), req.Name, req.Slug)
	if err != nil {
		return nil, err
	}

	lists, err := internalaccess.All()
	if err != nil {
		return nil, err
	}
	// Validate against the stored lists so the slug cannot collide.
	if err = internalaccess.Validate(plan.List, lists); err != nil {
		return nil, err
	}

	exists, err := nginx.Exists(internalaccess.FilePath(plan.List.Slug))
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, cosy.WrapErrorWithParams(internalaccess.ErrConvertListFileExists, plan.List.Slug)
	}
	return plan, nil
}

// PreviewSiteAccessConversion extracts the allow and deny rules of the chosen
// block and reports the new list, its file and the configuration diff. Nothing
// is written.
func PreviewSiteAccessConversion(c *gin.Context) {
	name := helper.UnescapeURL(c.Param("name"))
	if isInvalidConversionSiteName(name) {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid site name"})
		return
	}
	var req accessConversionRequest
	if !cosy.BindAndValid(c, &req) {
		return
	}

	_, path, err := loadConvertibleSite(name)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}
	content, err := readSiteForConversion(path)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}
	plan, err := prepareConversion(content, req)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	c.JSON(http.StatusOK, accessConversionResponse{
		Token:        internalaccess.ConversionToken(name, content, req.target(), req.Name, req.Slug),
		Server:       req.Server,
		Location:     req.Location,
		ServerName:   plan.ServerName,
		LocationPath: plan.LocationPath,
		Name:         plan.List.Name,
		Slug:         plan.List.Slug,
		Fallback:     plan.List.Fallback,
		Rules:        plan.List.Rules,
		ListContent:  plan.ListContent,
		Content:      plan.Content,
		Diff:         plan.Diff,
	})
}

// CommitSiteAccessConversion creates the previewed access list, writes its
// file and swaps the rules in the site configuration for an include, all in
// that order. Any failure restores both files and the database to their
// previous state.
func CommitSiteAccessConversion(c *gin.Context) {
	name := helper.UnescapeURL(c.Param("name"))
	if isInvalidConversionSiteName(name) {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid site name"})
		return
	}
	var req accessConversionRequest
	if !cosy.BindAndValid(c, &req) {
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		cosy.ErrHandler(c, internalaccess.ErrConvertStale)
		return
	}

	record, path, err := loadConvertibleSite(name)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}
	content, err := readSiteForConversion(path)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	// The token covers the file content and every conversion input, so a
	// changed site file or a changed name or identifier forces a new preview.
	if req.Token != internalaccess.ConversionToken(name, content, req.target(), req.Name, req.Slug) {
		cosy.ErrHandler(c, internalaccess.ErrConvertStale)
		return
	}

	plan, err := prepareConversion(content, req)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	enabledPath, err := site.ResolveEnabledPath(name)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}
	enabled, err := nginx.Exists(enabledPath)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	// Snapshot both files before writing anything. The list file must not
	// exist (prepareConversion rejected it), so its snapshot removes it again.
	siteSnapshot, err := config.CaptureFile(path)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}
	listPath := internalaccess.FilePath(plan.List.Slug)
	listSnapshot, err := config.CaptureFile(listPath)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	if err = nginx.MkdirAll(internalaccess.Dir(), 0o755); err != nil {
		cosy.ErrHandler(c, cosy.WrapErrorWithParams(internalaccess.ErrWriteAccessListFile, err.Error()))
		return
	}
	// Write the list file first, so the rewritten site configuration includes
	// a file that static validation and `nginx -t` can resolve.
	if err = nginx.WriteFile(listPath, []byte(plan.ListContent), 0o644); err != nil {
		_ = listSnapshot.Restore(listPath)
		cosy.ErrHandler(c, cosy.WrapErrorWithParams(internalaccess.ErrWriteAccessListFile, err.Error()))
		return
	}

	// Save through the regular site path: static validation, history, test and
	// reload for enabled sites, disabled sites untouched. It rolls the site
	// file back on its own failures; the new list file still has to go.
	if err = site.Save(c.Request.Context(), name, plan.Content, true,
		record.NamespaceID, record.SyncNodeIDs, model.PostSyncActionReloadNginx); err != nil {
		_ = listSnapshot.Restore(listPath)
		cosy.ErrHandler(c, err)
		return
	}

	// The running Nginx already accepted the configuration, so persist the
	// list last. A database failure undoes the site change (and reloads an
	// enabled site) and removes the file again.
	if err = model.UseDB().Create(plan.List).Error; err != nil {
		rollback := func() error {
			var errs []error
			if enabled {
				if restoreErr := config.RestoreAndReload(path, siteSnapshot); restoreErr != nil {
					errs = append(errs, restoreErr)
				}
			} else if restoreErr := siteSnapshot.Restore(path); restoreErr != nil {
				errs = append(errs, restoreErr)
			}
			// Keep the list file when the site could not be restored, because
			// the site on disk still includes it.
			if len(errs) == 0 {
				if removeErr := listSnapshot.Restore(listPath); removeErr != nil && !os.IsNotExist(removeErr) {
					errs = append(errs, removeErr)
				}
			}
			return errors.Join(errs...)
		}
		cosy.ErrHandler(c, config.RollbackError(err, rollback))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
		"list":    accessListItem{AccessList: plan.List, Warnings: internalaccess.Warnings(plan.List)},
		"content": plan.Content,
	})
}
