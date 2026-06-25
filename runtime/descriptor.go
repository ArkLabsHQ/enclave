package runtime

import "crypto/sha256"

const descriptorSchemaV1 = "enclave.deployment_descriptor.v1"

// deploymentDescriptorV1 is the out-of-band-pinnable root of trust: the genesis
// PCR0 plus the canonical lineage/anchor bucket names (+ region for credential-less
// anonymous S3). The genesis enclave attests sha256(canonicalCBOR(this)) in its
// lineage entry's self-attestation user_data, so a pinned descriptor is verifiable
// against the immutable chain.
type deploymentDescriptorV1 struct {
	Schema        string `cbor:"schema" json:"schema"`
	Deployment    string `cbor:"deployment" json:"deployment"`
	App           string `cbor:"app" json:"app"`
	Region        string `cbor:"region" json:"region"`
	GenesisPCR0   string `cbor:"genesis_pcr0" json:"genesis_pcr0"`
	AnchorBucket  string `cbor:"anchor_bucket" json:"anchor_bucket"`
	LineageBucket string `cbor:"lineage_bucket" json:"lineage_bucket"`
}

// descriptorHash is the value bound into the genesis self-attestation's user_data.
func descriptorHash(d deploymentDescriptorV1) ([]byte, error) {
	b, err := canonicalCBOR.Marshal(d)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}
