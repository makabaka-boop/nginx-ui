package certificate

import (
	"net/http"

	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/gin-gonic/gin"
	"github.com/uozi-tech/cosy"
)

type previewCertBatchReplaceRequest struct {
	OldCertificateID uint64 `json:"old_certificate_id" binding:"required"`
	NewCertificateID uint64 `json:"new_certificate_id" binding:"required"`
}

// PreviewBatchReplaceCert returns the sites that directly reference the old
// certificate, whether each site is eligible, and the per-server diff the
// replacement would produce. It never changes the configuration.
func PreviewBatchReplaceCert(c *gin.Context) {
	var json previewCertBatchReplaceRequest
	if !cosy.BindAndValid(c, &json) {
		return
	}

	preview, err := site.PreviewCertificateBatchReplace(json.OldCertificateID, json.NewCertificateID)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	c.JSON(http.StatusOK, preview)
}

type certBatchReplaceSiteRequest struct {
	Name        string `json:"name" binding:"required"`
	ContentHash string `json:"content_hash" binding:"required"`
}

type certBatchReplaceRequest struct {
	OldCertificateID   uint64                        `json:"old_certificate_id" binding:"required"`
	NewCertificateID   uint64                        `json:"new_certificate_id" binding:"required"`
	NewCertificateHash string                        `json:"new_certificate_hash" binding:"required"`
	Sites              []certBatchReplaceSiteRequest `json:"sites" binding:"required,min=1"`
}

// BatchReplaceCert replaces the old certificate and key paths with the new
// ones across every selected site as one batch, validates the configuration,
// and reloads Nginx. Any write, test or reload failure restores the whole
// batch.
func BatchReplaceCert(c *gin.Context) {
	var json certBatchReplaceRequest
	if !cosy.BindAndValid(c, &json) {
		return
	}

	selections := make([]site.CertificateBatchReplaceSelection, 0, len(json.Sites))
	for _, item := range json.Sites {
		selections = append(selections, site.CertificateBatchReplaceSelection{
			Name:        item.Name,
			ContentHash: item.ContentHash,
		})
	}

	updated, err := site.ApplyCertificateBatchReplace(
		json.OldCertificateID, json.NewCertificateID, json.NewCertificateHash, selections)
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"updated": updated})
}
