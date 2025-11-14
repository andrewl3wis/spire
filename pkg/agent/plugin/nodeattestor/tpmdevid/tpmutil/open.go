//go:build !windows

package tpmutil

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// openTPM open a channel to the TPM at the given path.
func openTPM(paths ...string) (transport.TPMCloser, error) {
	if len(paths) == 0 || paths[0] == "" {
		return nil, fmt.Errorf("TPM device path is required")
	}
	return linuxtpm.Open(paths[0])
}

// closeTPM checks if the TPM closer is a simulator that doesn't need closing.
// For now, all closers should be closed, so this returns false.
func closeTPM(closer transport.TPMCloser) bool {
	// With the new transport API, all TPM closers should be properly closed
	return false
}
