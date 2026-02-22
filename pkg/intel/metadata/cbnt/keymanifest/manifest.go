// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntkey

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// PrettyString: CBnT Key Manifest
type CBnTManifest struct {
	//cbnt.StructInfo `id:"__KEYM__" version:"0x21" var0:"0" var1:"0"`
	// KeyManifestSignatureOffset is Key Manifest KeySignature offset.
	//
	// The original name is "KeySignatureOffset" (in #575623).
	KeyManifestSignatureOffset uint16 `rehashValue:"KeyAndSignatureOffset()" json:"kmSigOffset,omitempty"`
	// Reserved2 is an alignment.
	Reserved2 [3]byte `json:"kmReserved2,omitempty"`
	// Revision is the revision of the Key Manifest defined by the Platform
	// Manufacturer.
	Revision uint8 `json:"kmRevision"`
	// PubKeyHashAlg is the hash algorithm of OEM public key digest programmed
	// into the FPF.
	PubKeyHashAlg cbnt.Algorithm `json:"kmPubKeyHashAlg"`

	// Hash is the slice of KMHASH_STRUCT (KHS) structures (see table 5-3
	// of the document #575623). Describes BPM pubkey digest (among other).
	Hash []Hash `json:"kmHash"`
}

// PrettyString: BG Key Manifest
type BGManifest struct {
	//cbnt.StructInfo `id:"__KEYM__" version:"0x10"`
	KMVersion uint8              `json:"kmVersion"`
	BPKey     cbnt.HashStructure `json:"kmBPKey"`
}

type Manifest struct {
	cbnt.StructInfo `id:"__KEYM__"`
	BGKM            BGManifest
	CBnTKM          CBnTManifest
	// KMSVN is the Key Manifest Security Version Number.
	KMSVN cbnt.SVN `json:"kmSVN"`
	// KMID is the Key Manifest Identifier.
	KMID uint8 `json:"kmID"`
	// KeyAndSignature is the Key Manifest signature.
	KeyAndSignature cbnt.KeySignature `json:"kmKeySignature"`
}

func (m *Manifest) SetSignature(
	algo cbnt.Algorithm,
	hashAlgo cbnt.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, hashAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	m.CBnTKM.PubKeyHashAlg = m.KeyAndSignature.Signature.HashAlg

	return nil
}

// Little helper to help generalize between versions
func validate(val cbnt.HashStructure, bpmKS cbnt.KeySignature) error {
	h, err := val.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash algo %v: %w", val.HashAlg, err)
	}

	if len(val.HashBuffer) != h.Size() {
		return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(val.HashBuffer), h.Size())
	}

	switch bpmKS.Key.KeyAlg {
	case cbnt.AlgRSA:
		if _, err := h.Write(bpmKS.Key.Data[4:]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key algorithm: %v", bpmKS.Key.KeyAlg)
	}
	digest := h.Sum(nil)

	if !bytes.Equal(val.HashBuffer, digest) {
		return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, val.HashBuffer, val.HashAlg)
	}

	return nil
}

func (m *Manifest) ValidateBPMKey(bpmKS cbnt.KeySignature) error {
	// TODO: think about smart way of handling this. Func signature
	// here makes it quite challenging to support both without braking
	// all callers...
	hashCount := 0
	for _, hashEntry := range m.CBnTKM.Hash {
		if !hashEntry.Usage.IsSet(UsageBPMSigningPKD) {
			continue
		}

		err := validate(hashEntry.Digest, bpmKS)
		if err != nil {
			return err
		}

		hashCount++
	}

	if hashCount == 0 {
		return fmt.Errorf("no hash of BPM's key was found in KM")
	}

	return nil
}

func (m *Manifest) Print() {
	// if m.KeyAndSignature.Signature.DataTotalSize() < 1 {
	// 	fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
	// 	fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	// } else {
	// 	fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	// }
	fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
}
