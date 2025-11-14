package tpmdevid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
)

func newNonce(size int) ([]byte, error) {
	nonce, err := devid.GetRandomBytes(size)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func VerifyDevIDChallenge(cert *x509.Certificate, challenge, response []byte) error {
	var signAlg x509.SignatureAlgorithm
	switch publicKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		signAlg = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		signAlg = x509.ECDSAWithSHA256
	default:
		return fmt.Errorf("unsupported private key type %T", publicKey)
	}
	return cert.CheckSignature(signAlg, challenge, response)
}

func NewCredActivationChallenge(akPub, ekPub tpm2.TPMTPublic) (*devid.CredActivation, []byte, error) {
	// Compute AK name
	akName, err := tpm2.ObjectName(&akPub)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot extract name from AK public: %w", err)
	}

	// Determine hash size
	hashAlg, err := akPub.NameAlg.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get hash algorithm: %w", err)
	}
	hashSize := hashAlg.Size()

	nonce, err := newNonce(hashSize)
	if err != nil {
		return nil, nil, err
	}

	// Convert EK public key to LabeledEncapsulationKey
	encKey, err := tpm2.ImportEncapsulationKey(&ekPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to import EK as encapsulation key: %w", err)
	}

	// Generate credential activation challenge
	credentialBlob, secret, err := tpm2.CreateCredential(
		rand.Reader,
		encKey,
		akName.Buffer,
		nonce,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create credential: %w", err)
	}

	return &devid.CredActivation{
		Credential: credentialBlob,
		Secret:     secret,
	}, nonce, nil
}

func VerifyCredActivationChallenge(expectedNonce, responseNonce []byte) error {
	if !bytes.Equal(expectedNonce, responseNonce) {
		return errors.New("nonces are different")
	}

	return nil
}
