package tpmutil

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// maxAttempts indicates the max number retries for running TPM commands when
// TPM responds with a tpm2.RCRetry code.
const maxAttempts = 10

// SigningKey represents a TPM loaded key
type SigningKey struct {
	Handle     tpm2.TPMHandle
	Name       tpm2.TPM2BName
	sigHashAlg tpm2.TPMIAlgHash
	tpm        transport.TPM
	log        hclog.Logger
	password   string
}

// Close removes the key from the TPM
func (k *SigningKey) Close() error {
	flushCmd := tpm2.FlushContext{
		FlushHandle: k.Handle,
	}
	_, err := flushCmd.Execute(k.tpm)
	return err
}

// Sign requests the TPM to sign the given data using this key
func (k *SigningKey) Sign(data []byte) ([]byte, error) {
	// Hash the data
	hashCmd := tpm2.Hash{
		Data: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		HashAlg:   k.sigHashAlg,
		Hierarchy: tpm2.TPMRHOwner,
	}
	hashRsp, err := hashCmd.Execute(k.tpm)
	if err != nil {
		return nil, fmt.Errorf("hash failed: %w", err)
	}

	for i := 1; i <= maxAttempts; i++ {
		signCmd := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: k.Handle,
				Name:   k.Name,
				Auth:   tpm2.PasswordAuth([]byte(k.password)),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: hashRsp.OutHash.Buffer,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgNull,
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}

		signRsp, err := signCmd.Execute(k.tpm)
		switch {
		case err == nil:
			return getSignatureBytes(&signRsp.Signature)

		case isRetry(err):
			k.log.Warn(fmt.Sprintf("TPM was not able to start the command 'Sign'. Retrying: attempt (%d/%d)", i, maxAttempts))
			time.Sleep(time.Millisecond * 500)
			continue

		default:
			return nil, fmt.Errorf("sign failed: %w", err)
		}
	}

	return nil, errors.New("max attempts reached while trying to sign payload")
}

// Certify calls tpm2.Certify using the current key as signer and the provided
// handle as object.
func (k *SigningKey) Certify(objectHandle tpm2.TPMHandle, objectName tpm2.TPM2BName, objectPassword string) ([]byte, []byte, error) {
	// For some reason 'tpm2.Certify()' sometimes fails the first attempt and asks for retry.
	// So, we retry in case of getting the RCRetry error.
	// It seems that this issue has been reported: https://github.com/google/go-tpm/issues/59
	for i := 1; i <= maxAttempts; i++ {
		certifyCmd := tpm2.Certify{
			ObjectHandle: tpm2.AuthHandle{
				Handle: objectHandle,
				Name:   objectName,
				Auth:   tpm2.PasswordAuth([]byte(objectPassword)),
			},
			SignHandle: tpm2.AuthHandle{
				Handle: k.Handle,
				Name:   k.Name,
				Auth:   tpm2.PasswordAuth([]byte(k.password)),
			},
			QualifyingData: tpm2.TPM2BData{},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgNull,
			},
		}

		certifyRsp, err := certifyCmd.Execute(k.tpm)
		switch {
		case err == nil:
			return tpm2.Marshal(certifyRsp.CertifyInfo), tpm2.Marshal(certifyRsp.Signature), nil

		case isRetry(err):
			k.log.Warn(fmt.Sprintf("TPM was not able to start the command 'Certify'. Retrying: attempt (%d/%d)", i, maxAttempts))
			time.Sleep(time.Millisecond * 500)

		default:
			return nil, nil, fmt.Errorf("certify failed: %w", err)
		}
	}

	return nil, nil, errors.New("max attempts reached while trying to certify key")
}

// isRetry returns true if the given error is a TPM retry error.
func isRetry(err error) bool {
	var rc tpm2.TPMRC
	if errors.As(err, &rc) {
		return rc == tpm2.TPMRCRetry
	}
	return false
}

func getSignatureBytes(sig *tpm2.TPMTSignature) ([]byte, error) {
	switch sig.SigAlg {
	case tpm2.TPMAlgRSASSA, tpm2.TPMAlgRSAPSS:
		rsaSig, err := sig.Signature.RSASSA()
		if err != nil {
			rsaSig, err = sig.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("failed to get RSA signature: %w", err)
			}
		}
		return rsaSig.Sig.Buffer, nil

	case tpm2.TPMAlgECDSA:
		eccSig, err := sig.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("failed to get ECDSA signature: %w", err)
		}

		// Convert byte slices to big.Int
		r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
		s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

		var b cryptobyte.Builder
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(r)
			b.AddASN1BigInt(s)
		})

		return b.Bytes()

	default:
		return nil, fmt.Errorf("unrecognized signature algorithm: 0x%04x", sig.SigAlg)
	}
}
