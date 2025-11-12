package tpmutil

import (
	"github.com/google/go-tpm/tpm2"
)

// DefaultEKTemplateRSA returns the default RSA Endorsement Key template.
// This is the TCG reference RSA-2048 EK template as specified in the
// TCG EK Credential Profile specification.
func DefaultEKTemplateRSA() tpm2.TPMTPublic {
	return tpm2.RSAEKTemplate
}

// DefaultEKTemplateECC returns the default ECC Endorsement Key template.
// This is the TCG reference ECC-P256 EK template as specified in the
// TCG EK Credential Profile specification.
func DefaultEKTemplateECC() tpm2.TPMTPublic {
	return tpm2.ECCEKTemplate
}

// SRKTemplateRSA returns the default RSA Storage Root Key template.
// This is the TCG reference RSA-2048 SRK template.
func SRKTemplateRSA() tpm2.TPMTPublic {
	return tpm2.RSASRKTemplate
}

// SRKTemplateECC returns the default ECC Storage Root Key template.
// This is the TCG reference ECC-P256 SRK template.
func SRKTemplateECC() tpm2.TPMTPublic {
	return tpm2.ECCSRKTemplate
}

// AKTemplateRSA returns an RSA Attestation Key template.
// The AK is similar to the EK but is a signing key instead of a decrypting key.
func AKTemplateRSA() tpm2.TPMTPublic {
	template := tpm2.RSAEKTemplate
	// Change the template to be a signing/restricted key instead of decrypt
	template.ObjectAttributes.Decrypt = false
	template.ObjectAttributes.SignEncrypt = true
	template.ObjectAttributes.Restricted = true

	// Set the signing scheme
	template.Parameters = tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgRSA,
		&tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgRSASSA,
					&tpm2.TPMSSigSchemeRSASSA{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			},
			KeyBits:  2048,
			Exponent: 0,
		},
	)

	return template
}

// AKTemplateECC returns an ECC Attestation Key template.
// The AK is similar to the EK but is a signing key instead of a decrypting key.
func AKTemplateECC() tpm2.TPMTPublic {
	template := tpm2.ECCEKTemplate
	// Change the template to be a signing/restricted key instead of decrypt
	template.ObjectAttributes.Decrypt = false
	template.ObjectAttributes.SignEncrypt = true
	template.ObjectAttributes.Restricted = true

	// Set the signing scheme
	template.Parameters = tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF: tpm2.TPMTKDFScheme{
				Scheme: tpm2.TPMAlgNull,
			},
		},
	)

	return template
}
