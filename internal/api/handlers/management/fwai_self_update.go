package management

import (
	"errors"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/fwaiupdate"
	log "github.com/sirupsen/logrus"
)

// fwaiSelfUpdateMu keeps one update at a time.
var fwaiSelfUpdateMu sync.Mutex

// GetFwaiSelfUpdate reports whether this instance can update itself, the
// version running, and what is installed over its image.
func (h *Handler) GetFwaiSelfUpdate(c *gin.Context) {
	status := fwaiupdate.Current()
	c.JSON(http.StatusOK, gin.H{
		"available": status.Available,
		"running":   buildinfo.Version,
		"installed": status.Installed,
		"image":     status.Image,
	})
}

// PostFwaiSelfUpdate installs release {version} of this fork, checked against
// {sha256}, then stops the process for the container to restart on it. The
// answer goes out before the process stops.
func (h *Handler) PostFwaiSelfUpdate(c *gin.Context) {
	var body struct {
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if !fwaiSelfUpdateMu.TryLock() {
		c.JSON(http.StatusConflict, gin.H{"error": "an update is already in progress"})
		return
	}
	if err := fwaiupdate.Apply(c.Request.Context(), http.DefaultClient, body.Version, body.SHA256); err != nil {
		fwaiSelfUpdateMu.Unlock()
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, fwaiupdate.ErrUnavailable):
			status = http.StatusNotImplemented
		case errors.Is(err, fwaiupdate.ErrInvalid):
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	log.Warnf("self-update: installed %s over %s, restarting", body.Version, buildinfo.Version)
	c.JSON(http.StatusAccepted, gin.H{"version": body.Version, "restarting": true})
	// Held until the process goes: no second update in between.
	go func() {
		time.Sleep(time.Second)
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
}
