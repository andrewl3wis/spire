//go:build windows

package tpmutil

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openTPM open a channel to the TPM, Windows does not receive a path.
func openTPM(paths ...string) (transport.TPMCloser, error) {
	if len(paths) != 0 && paths[0] != "" {
		return nil, errors.New("open tpm does not allows to set a device path")
	}

	return windowstpm.Open()
}

// closeTPM we must close always when running on windows
func closeTPM(transport.TPMCloser) bool {
	return false
}
