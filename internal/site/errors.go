package site

import "github.com/uozi-tech/cosy"

var (
	e                       = cosy.NewErrorScope("site")
	ErrSiteNotFound         = e.New(40401, "site not found")
	ErrDstFileExists        = e.New(50001, "destination file already exists")
	ErrSiteIsEnabled        = e.New(50002, "site is enabled")
	ErrSiteIsInMaintenance  = e.New(50003, "site is in maintenance mode")
	ErrNginxTestFailed      = e.New(50004, "nginx test failed: {0}")
	ErrNginxReloadFailed    = e.New(50005, "nginx reload failed: {0}")
	ErrReadDirFailed        = e.New(50006, "read dir failed: {0}")
	ErrSiteManagedByIngress = e.New(40901, "site is managed by ingress {0}; change the ingress instead or force the change")

	ErrBatchReplaceCertificateNotFound = e.New(40410, "certificate not found")
	ErrBatchReplaceCertificateUnusable = e.New(40010, "{0}")
	ErrBatchReplaceSameCertificate     = e.New(40011, "the new certificate must be different from the old one")
	ErrBatchReplaceNoSitesSelected     = e.New(40012, "select at least one site")
	ErrBatchReplaceSiteUnavailable     = e.New(40910, "site {0} is not eligible for batch certificate replacement: {1}")
	ErrBatchReplacePreviewStale        = e.New(40911, "the site configuration or the certificate changed since the preview; preview again")
)
