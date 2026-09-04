package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// StartObserver creates the per-run internal network and starts the trusted
// observer sidecar. The sidecar is the only writer of TrustedVolumePrefix.
func (r *Runner) StartObserver(ctx context.Context, runID, image, seccomp string) error {
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: observer runID 非法：%q", runID)
	}
	if !digestRe.MatchString(image) {
		return fmt.Errorf("sandbox: observer image 須為 digest：%q", image)
	}
	if _, stderr, err := r.runCtx(ctx, 30*time.Second, "network", "create", "--internal", SSRFNetPrefix+runID); err != nil {
		return wrapErr("observer network create", stderr, err)
	}
	createdNetwork := true
	defer func() {
		// Successful start owns cleanup; failures must not strand a network or
		// volume even when the caller returns before Reclaim is installed.
		if createdNetwork {
			_ = r.StopObserver(runID)
		}
	}()
	if _, stderr, err := r.runCtx(ctx, 30*time.Second, "volume", "create", TrustedVolumePrefix+runID); err != nil {
		return wrapErr("observer volume create", stderr, err)
	}
	hardening, err := HardeningFlags(seccomp)
	if err != nil {
		return err
	}
	args := []string{"run", "-d", "--name", "aegis-observer-" + runID, "--label", LabelRunID + "=" + runID,
		"--network", SSRFNetPrefix + runID, "--network-alias", "observer", "-v", TrustedVolumePrefix + runID + ":/aegis/trusted"}
	args = append(args, hardening...)
	args = append(args, image, "/aegis/observer-proxy", "--listen", ":8787")
	if _, stderr, err := r.runCtx(ctx, 60*time.Second, args...); err != nil {
		return wrapErr("observer start", stderr, err)
	}
	createdNetwork = false
	return nil
}

// StopObserver removes the sidecar and trusted volume/network.
func (r *Runner) StopObserver(runID string) error {
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: observer runID 非法：%q", runID)
	}
	var first error
	if _, stderr, err := r.runTimeout(30*time.Second, "rm", "-f", "aegis-observer-"+runID); err != nil && !strings.Contains(strings.ToLower(string(stderr)), "no such container") {
		first = wrapErr("observer rm", stderr, err)
	}
	if err := r.removeVolumeRetry(TrustedVolumePrefix + runID); err != nil && first == nil {
		first = err
	}
	if _, stderr, err := r.runTimeout(30*time.Second, "network", "rm", SSRFNetPrefix+runID); err != nil && !strings.Contains(strings.ToLower(string(stderr)), "no such network") && first == nil {
		first = wrapErr("observer network rm", stderr, err)
	}
	return first
}
