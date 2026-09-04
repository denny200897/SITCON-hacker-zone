package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// StartObserver creates the per-run internal networks and starts the trusted
// observer sidecar. The sidecar is the only writer of TrustedVolumePrefix.
// With the ADR 0005 split it also creates the driver network (aegis-driver-<runID>):
// container T joins both, container W only the driver one, so model-generated
// code has no route to the observer.
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
	if _, stderr, err := r.runCtx(ctx, 30*time.Second, "network", "create", "--internal", DriverNetPrefix+runID); err != nil {
		return wrapErr("driver network create", stderr, err)
	}
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

// StopObserver removes the sidecar and the trusted volume plus both per-run
// internal networks (observer and driver, ADR 0005).
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
	for _, net := range []string{SSRFNetPrefix + runID, DriverNetPrefix + runID} {
		if _, stderr, err := r.runTimeout(30*time.Second, "network", "rm", net); err != nil && !strings.Contains(strings.ToLower(string(stderr)), "no such network") && first == nil {
			first = wrapErr("observer network rm", stderr, err)
		}
	}
	return first
}

// ConnectTargetNetwork attaches a created (not yet started) container to the
// per-run driver network with the fixed target alias (ADR 0005): container W
// reaches the trusted side only through this alias, and docker create accepts a
// single --network, so the second network is connected explicitly.
func (r *Runner) ConnectTargetNetwork(ctx context.Context, runID, cid string) error {
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: ConnectTargetNetwork 的 runID 非法：%q", runID)
	}
	if cid == "" {
		return fmt.Errorf("sandbox: ConnectTargetNetwork 的 cid 為空")
	}
	_, stderr, err := r.runCtx(ctx, 30*time.Second, "network", "connect", "--alias", "target", DriverNetPrefix+runID, cid)
	if err != nil {
		return wrapErr("network connect", stderr, err)
	}
	return nil
}
