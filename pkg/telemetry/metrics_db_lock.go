// Copyright 2023 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/vmware-tanzu/tanzu-cli/pkg/common"

	"github.com/juju/fslock"
)

const (
	LocalTanzuCLIMetricsDBFileLock = ".cli_metrics_db.lock"
	// DefaultMetricsDBLockTimeout is the default time waiting on the filelock
	DefaultMetricsDBLockTimeout = 3 * time.Second
)

var cliMetricDBLockFile string

// cliMetricDBLock used as a static lock variable that stores fslock
// This is used for interprocess locking of the tanzu cli metrics DB file
var cliMetricDBLock *fslock.Lock

// cliMetricDBMutex is used to handle the locking behavior between concurrent calls
// within the existing process trying to acquire the lock
var cliMetricDBMutex sync.Mutex

// AcquireTanzuMetricDBLock tries to acquire lock to update tanzu cli metrics DB file with timeout
func AcquireTanzuMetricDBLock() error {
	var err error

	if cliMetricDBLockFile == "" {
		cliMetricDBLockFile = filepath.Join(common.DefaultCLITelemetryDir, LocalTanzuCLIMetricsDBFileLock)
	}

	// using fslock to handle interprocess locking
	lock, err := getFileLockWithTimeout(cliMetricDBLockFile, DefaultMetricsDBLockTimeout)
	if err != nil {
		return fmt.Errorf("cannot acquire lock for Tanzu CLI metrics DB, reason: %v", err)
	}

	// Lock the mutex to prevent concurrent calls to acquire and configure the cliMetricDBLock
	cliMetricDBMutex.Lock()
	cliMetricDBLock = lock
	return nil
}

// ReleaseTanzuMetricDBLock releases the lock if the cliMetricDBLock was acquired
func ReleaseTanzuMetricDBLock() {
	if cliMetricDBLock == nil {
		return
	}
	if errUnlock := cliMetricDBLock.Unlock(); errUnlock != nil {
		panic(fmt.Sprintf("cannot release lock for Tanzu CLI metrics DB, reason: %v", errUnlock))
	}

	cliMetricDBLock = nil
	// Unlock the mutex to allow other concurrent calls to acquire and configure the cliMetricDBLock
	cliMetricDBMutex.Unlock()
}

// getFileLockWithTimeout returns a file lock with timeout
func getFileLockWithTimeout(lockPath string, lockDuration time.Duration) (*fslock.Lock, error) {
	dir := filepath.Dir(lockPath)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}

	lock := fslock.New(lockPath)

	if err := lock.LockWithTimeout(lockDuration); err != nil {
		return nil, errors.Wrap(err, "failed to acquire a lock with timeout")
	}
	return lock, nil
}
