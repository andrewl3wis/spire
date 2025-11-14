package tpmutil

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
)

// ekRSACertificateHandle is the default handle for RSA endorsement key according
// to the TCG TPM v2.0 Provisioning Guidance, section 7.8
// https://trustedcomputinggroup.org/resource/tcg-tpm-v2-0-provisioning-guidance/
const EKCertificateHandleRSA = tpm2.TPMHandle(0x01c00002)

// randomPasswordSize is the number of bytes of generated random passwords
const randomPasswordSize = 32

// Session represents a TPM with loaded DevID credentials and exposes methods
// to perform cryptographic operations relevant to the SPIRE node attestation
// workflow.
type Session struct {
	devID    *SigningKey
	ak       *SigningKey
	ekHandle tpm2.TPMHandle
	ekName   tpm2.TPM2BName
	ekPub    []byte
	akPub    []byte

	endorsementHierarchyPassword string
	ownerHierarchyPassword       string

	tpm transport.TPM
	log hclog.Logger
}

type TPMPasswords struct {
	EndorsementHierarchy string
	OwnerHierarchy       string
	DevIDKey             string
}

type SessionConfig struct {
	// in future iterations of tpm libraries, TPM will accept a
	// list of device paths (https://github.com/google/go-tpm/pull/256)
	DevicePath string
	DevIDPriv  []byte
	DevIDPub   []byte
	Passwords  TPMPasswords
	Log        hclog.Logger
}

var OpenTPM = openTPM

// NewSession opens a connection to a TPM and configures it to be used for
// node attestation.
func NewSession(scfg *SessionConfig) (*Session, error) {
	if scfg.Log == nil {
		return nil, errors.New("missing logger")
	}

	// Open TPM connection
	tpmTransport, err := OpenTPM(scfg.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM at %q: %w", scfg.DevicePath, err)
	}

	// Create session
	sess := &Session{
		tpm:                          tpmTransport,
		log:                          scfg.Log,
		endorsementHierarchyPassword: scfg.Passwords.EndorsementHierarchy,
		ownerHierarchyPassword:       scfg.Passwords.OwnerHierarchy,
	}

	// Close session in case of error
	defer func() {
		if err != nil {
			sess.Close()
		}
	}()

	// Create SRK password
	srkPassword, err := newRandomPassword()
	if err != nil {
		return nil, fmt.Errorf("cannot generate random password for storage root key: %w", err)
	}

	// Load DevID
	sess.devID, err = sess.loadKey(
		scfg.DevIDPub,
		scfg.DevIDPriv,
		srkPassword,
		scfg.Passwords.DevIDKey)
	if err != nil {
		return nil, fmt.Errorf("cannot load DevID key on TPM: %w", err)
	}

	// Create Attestation Key
	akPassword, err := newRandomPassword()
	if err != nil {
		return nil, fmt.Errorf("cannot generate random password for attestation key: %w", err)
	}
	akPriv, akPub, err := sess.createAttestationKey(srkPassword, akPassword)
	if err != nil {
		return nil, fmt.Errorf("cannot create attestation key: %w", err)
	}
	sess.akPub = akPub

	// Load Attestation Key
	sess.ak, err = sess.loadKey(
		akPub,
		akPriv,
		srkPassword,
		akPassword)
	if err != nil {
		return nil, fmt.Errorf("cannot load attestation key: %w", err)
	}

	// Regenerate Endorsement Key using the default RSA template
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth([]byte(scfg.Passwords.EndorsementHierarchy)),
		},
		InPublic: tpm2.New2B(DefaultEKTemplateRSA()),
	}
	createEKRsp, err := createEKCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("cannot create endorsement key: %w", err)
	}
	sess.ekHandle = createEKRsp.ObjectHandle
	sess.ekName = createEKRsp.Name

	// Get the inner TPMTPublic from the TPM2BPublic wrapper
	ekPublicContents, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("cannot get EK public key contents: %w", err)
	}
	sess.ekPub = tpm2.Marshal(*ekPublicContents)

	return sess, nil
}

// Close unloads TPM loaded objects and closes the connection to the TPM.
func (c *Session) Close() {
	if c.devID != nil {
		err := c.devID.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close DevID handle: %v", err))
		}
	}

	if c.ak != nil {
		err := c.ak.Close()
		if err != nil {
			c.log.Warn(fmt.Sprintf("Failed to close attestation key handle: %v", err))
		}
	}

	if c.ekHandle != 0 {
		c.flushContext(c.ekHandle)
	}

	if c.tpm != nil {
		if tpmCloser, ok := c.tpm.(transport.TPMCloser); ok {
			if closeTPM(tpmCloser) {
				return
			}

			err := tpmCloser.Close()
			if err != nil {
				c.log.Warn(fmt.Sprintf("Failed to close TPM: %v", err))
			}
		}
	}
}

// SolveDevIDChallenge requests the TPM to sign the provided nonce using the loaded
// DevID credentials.
func (c *Session) SolveDevIDChallenge(nonce []byte) ([]byte, error) {
	signedNonce, err := c.devID.Sign(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to sign nonce: %w", err)
	}

	return signedNonce, nil
}

// SolveCredActivationChallenge runs credential activation on the TPM. It proves
// that the attestation key resides on the same TPM as the endorsement key.
func (c *Session) SolveCredActivationChallenge(credentialBlob, secret []byte) ([]byte, error) {
	policySession, cleanup, err := c.createPolicySessionForEK()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	activateCmd := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{
			Handle: c.ak.Handle,
			Name:   c.ak.Name,
			Auth:   tpm2.PasswordAuth([]byte(c.ak.password)),
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: c.ekHandle,
			Name:   c.ekName,
			Auth:   policySession,
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: secret},
	}

	rsp, err := activateCmd.Execute(c.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %w", err)
	}

	return rsp.CertInfo.Buffer, nil
}

// CertifyDevIDKey proves that the DevID Key is in the same TPM than
// Attestation Key.
func (c *Session) CertifyDevIDKey() ([]byte, []byte, error) {
	return c.ak.Certify(c.devID.Handle, c.devID.Name, c.devID.password)
}

// GetEKCert returns TPM endorsement certificate.
func (c *Session) GetEKCert() ([]byte, error) {
	// Read the NV index to get the size first
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: EKCertificateHandleRSA,
	}
	readPubRsp, err := readPubCmd.Execute(c.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV public for index %08x: %w", EKCertificateHandleRSA, err)
	}

	nvPublic, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get NV public contents: %w", err)
	}

	// Read the full certificate
	nvReadCmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: EKCertificateHandleRSA,
			Name:   readPubRsp.NVName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: EKCertificateHandleRSA,
			Name:   readPubRsp.NVName,
		},
		Size:   nvPublic.DataSize,
		Offset: 0,
	}
	nvReadRsp, err := nvReadCmd.Execute(c.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV index %08x: %w", EKCertificateHandleRSA, err)
	}

	ekCertAndTrailingBytes := nvReadRsp.Data.Buffer

	// In some TPMs, when we read bytes from an NV index, the content read
	// includes the DER encoded x.509 certificate + trailing data. We need to
	// remove those trailing bytes in order to make the certificate parseable by
	// the server that uses x509.ParseCertificate().
	var ekCert asn1.RawValue
	_, err = asn1.Unmarshal(ekCertAndTrailingBytes, &ekCert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall certificate read from %08x: %w", EKCertificateHandleRSA, err)
	}

	return ekCert.FullBytes, nil
}

// GetEKPublic returns the public part of the Endorsement Key encoded in
// TPM wire format.
func (c *Session) GetEKPublic() ([]byte, error) {
	return c.ekPub, nil
}

// GetAKPublic returns the public part of the attestation key encoded in
// TPM wire format.
func (c *Session) GetAKPublic() []byte {
	return c.akPub
}

// loadKey loads a key pair into the TPM.
func (c *Session) loadKey(publicKey, privateKey []byte, parentKeyPassword, keyPassword string) (*SigningKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	canSign := pub.ObjectAttributes.SignEncrypt
	if !canSign {
		return nil, errors.New("not a signing key")
	}

	var sigHashAlg tpm2.TPMIAlgHash
	var srkTemplate tpm2.TPMTPublic
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		srkTemplate = SRKTemplateRSA()
		rsaParams, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("failed to get RSA parameters: %w", err)
		}
		sigScheme, err := rsaParams.Scheme.Details.RSASSA()
		if err == nil {
			sigHashAlg = sigScheme.HashAlg
		}

	case tpm2.TPMAlgECC:
		srkTemplate = SRKTemplateECC()
		eccParams, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("failed to get ECC parameters: %w", err)
		}
		sigScheme, err := eccParams.Scheme.Details.ECDSA()
		if err == nil {
			sigHashAlg = sigScheme.HashAlg
		}

	default:
		return nil, fmt.Errorf("bad key type: 0x%04x", pub.Type)
	}

	if sigHashAlg == tpm2.TPMAlgNull {
		return nil, errors.New("signature hash algorithm is NULL")
	}

	// Create SRK
	createSRKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(c.ownerHierarchyPassword)),
		},
		InPublic: tpm2.New2B(srkTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(parentKeyPassword),
				},
			},
		},
	}
	createSRKRsp, err := createSRKCmd.Execute(c.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRK: %w", err)
	}
	defer c.flushContext(createSRKRsp.ObjectHandle)

	// Load the key
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   tpm2.PasswordAuth([]byte(parentKeyPassword)),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: privateKey},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](publicKey),
	}
	loadRsp, err := loadCmd.Execute(c.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	return &SigningKey{
		Handle:     loadRsp.ObjectHandle,
		Name:       loadRsp.Name,
		sigHashAlg: sigHashAlg,
		tpm:        c.tpm,
		log:        c.log,
		password:   keyPassword,
	}, nil
}

func (c *Session) createAttestationKey(parentKeyPassword, keyPassword string) ([]byte, []byte, error) {
	// Create SRK
	createSRKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(c.ownerHierarchyPassword)),
		},
		InPublic: tpm2.New2B(SRKTemplateRSA()),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(parentKeyPassword),
				},
			},
		},
	}
	createSRKRsp, err := createSRKCmd.Execute(c.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SRK: %w", err)
	}
	defer c.flushContext(createSRKRsp.ObjectHandle)

	// Create AK
	createAKCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: createSRKRsp.ObjectHandle,
			Name:   createSRKRsp.Name,
			Auth:   tpm2.PasswordAuth([]byte(parentKeyPassword)),
		},
		InPublic: tpm2.New2B(AKTemplateRSA()),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(keyPassword),
				},
			},
		},
	}
	createAKRsp, err := createAKCmd.Execute(c.tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AK: %w", err)
	}

	// Get the inner TPMTPublic from the TPM2BPublic wrapper
	publicContents, err := createAKRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get AK public key contents: %w", err)
	}

	return createAKRsp.OutPrivate.Buffer, tpm2.Marshal(*publicContents), nil
}

// createPolicySessionForEK creates a session-based authorization to access EK.
// We need a session-based authorization to run the activate credential command
// (password-based auth is not enough) because of the attributes of the EK template.
// Returns the session and a cleanup function.
func (c *Session) createPolicySessionForEK() (tpm2.Session, func(), error) {
	// The TPM is accessed in a plain session (we assume the bus is trusted) so we use an:
	// un-bounded and un-salted policy session (bindKey = HandleNull, tpmKey = HandleNull, secret = nil,
	// (sym = algNull, nonceCaller = all zeros).

	// Create a policy session that applies policy secret for endorsement hierarchy
	policyCallback := func(tpm transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
		// Apply policy secret to authorize with endorsement hierarchy
		policySecretCmd := tpm2.PolicySecret{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHEndorsement,
				Auth:   tpm2.PasswordAuth([]byte(c.endorsementHierarchyPassword)),
			},
			PolicySession: handle,
		}
		_, err := policySecretCmd.Execute(tpm)
		return err
	}

	// Create session object with the policy callback
	session := tpm2.Policy(tpm2.TPMAlgSHA256, 16, policyCallback)

	// No cleanup needed - the Policy session is ephemeral and cleaned up automatically
	cleanup := func() {}

	return session, cleanup, nil
}

func (c *Session) flushContext(handle tpm2.TPMHandle) {
	flushCmd := tpm2.FlushContext{
		FlushHandle: handle,
	}
	_, err := flushCmd.Execute(c.tpm)
	if err != nil {
		c.log.Warn(fmt.Sprintf("Failed to flush handle %v: %v", handle, err))
	}
}

func newRandomPassword() (string, error) {
	rndBytes, err := tpmdevid.GetRandomBytes(randomPasswordSize)
	if err != nil {
		return "", err
	}
	return string(rndBytes), nil
}
