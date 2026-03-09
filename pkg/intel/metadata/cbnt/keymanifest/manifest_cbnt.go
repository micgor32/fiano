// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntkey

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// PrettyString: CBnT Key Manifest
type CBnTManifest struct {
	cbnt.Common
	cbnt.StructInfoCBNT `id:"__KEYM__" version:"0x21" var0:"0" var1:"0"`

	// KeyManifestSignatureOffset is Key Manifest KeySignature offset.
	//
	// The original name is "KeySignatureOffset" (in #575623).
	KeyManifestSignatureOffset uint16 `rehashValue:"KeyAndSignatureOffset()" json:"kmSigOffset,omitempty"`

	// Reserved2 is an alignment.
	Reserved2 [3]byte `json:"kmReserved2,omitempty"`

	// Revision is the revision of the Key Manifest defined by the Platform
	// Manufacturer.
	Revision uint8 `json:"kmRevision"`

	// KMSVN is the Key Manifest Security Version Number.
	KMSVN cbnt.SVN `json:"kmSVN"`

	// KMID is the Key Manifest Identifier.
	KMID uint8 `json:"kmID"`

	// PubKeyHashAlg is the hash algorithm of OEM public key digest programmed
	// into the FPF.
	PubKeyHashAlg cbnt.Algorithm `json:"kmPubKeyHashAlg"`

	// Hash is the slice of KMHASH_STRUCT (KHS) structures (see table 5-3
	// of the document #575623). Describes BPM pubkey digest (among other).
	Hash []Hash `json:"kmHash"`

	// KeyAndSignature is the Key Manifest signature.
	KeyAndSignature cbnt.KeySignature `json:"kmKeySignature"`
}

func (m *CBnTManifest) SetSignature(
	algo cbnt.Algorithm,
	hashAlgo cbnt.Algorithm,
	privKey crypto.Signer,
	signedData []byte,
) error {
	err := m.KeyAndSignature.SetSignature(algo, hashAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}
	m.PubKeyHashAlg = m.KeyAndSignature.Signature.HashAlg

	return nil
}

func (m *CBnTManifest) ValidateBPMKey(bpmKS cbnt.KeySignature) error {
	hashCount := 0
	for _, hashEntry := range m.Hash {
		if !hashEntry.Usage.IsSet(UsageBPMSigningPKD) {
			continue
		}

		h, err := hashEntry.Digest.HashAlg.Hash()
		if err != nil {
			return fmt.Errorf("invalid hash algo %v: %w", hashEntry.Digest.HashAlg, err)
		}

		if len(hashEntry.Digest.HashBuffer) != h.Size() {
			return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(hashEntry.Digest.HashBuffer), h.Size())
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

		if !bytes.Equal(hashEntry.Digest.HashBuffer, digest) {
			return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, hashEntry.Digest.HashBuffer, hashEntry.Digest.HashAlg)
		}
		hashCount++
	}

	if hashCount == 0 {
		return fmt.Errorf("no hash of BPM's key was found in KM")
	}

	return nil
}

func (s *CBnTManifest) Validate() error {
	v, err := s.OffsetOf(8)
	if err != nil {
		return fmt.Errorf("error on field 'KeyAndSignature': %w", err)
	}
	expectedValue := uint16(v)
	if s.KeyManifestSignatureOffset != expectedValue {
		return fmt.Errorf("field 'KeyManifestSignatureOffset' expects write-value '%v', but has %v", expectedValue, s.KeyManifestSignatureOffset)
	}
	// Recursively validating a child structure:
	if err := s.KeyAndSignature.Validate(); err != nil {
		return fmt.Errorf("error on field 'KeyAndSignature': %w", err)
	}

	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *CBnTManifest) GetStructInfo() cbnt.StructInfo {
	return s.StructInfoCBNT
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *CBnTManifest) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfoCBNT = newStructInfo.(cbnt.StructInfoCBNT)
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (s *CBnTManifest) ReadFrom(r io.Reader) (int64, error) {
	return s.Common.ReadFrom(r, s)
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *CBnTManifest) RehashRecursive() {
	s.KeyAndSignature.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *CBnTManifest) Rehash() {
	s.Variable0 = 0
	s.ElementSize = 0
	v, err := s.OffsetOf(8)
	if err != nil {
		// TODO: this will never be true, but still lets think of how to handle
	}
	s.KeyManifestSignatureOffset = uint16(v)
}

// WriteTo writes the Manifest into 'w' in format defined in
// the document #575623.
func (s *CBnTManifest) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// StructInfo (ManifestFieldType: structInfo)
	{
		n, err := s.StructInfoCBNT.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'StructInfo': %w", err)
		}
		totalN += int64(n)
	}

	// KeyManifestSignatureOffset (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeyManifestSignatureOffset)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyManifestSignatureOffset': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved2 (ManifestFieldType: arrayStatic)
	{
		n, err := 3, binary.Write(w, binary.LittleEndian, s.Reserved2[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved2': %w", err)
		}
		totalN += int64(n)
	}

	// Revision (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.Revision)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Revision': %w", err)
		}
		totalN += int64(n)
	}

	// KMSVN (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.KMSVN)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KMSVN': %w", err)
		}
		totalN += int64(n)
	}

	// KMID (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.KMID)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KMID': %w", err)
		}
		totalN += int64(n)
	}

	// PubKeyHashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.PubKeyHashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PubKeyHashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Hash (ManifestFieldType: list)
	{
		count := uint16(len(s.Hash))
		err := binary.Write(w, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the count for field 'Hash': %w", err)
		}
		totalN += int64(binary.Size(count))
		for idx := range s.Hash {
			n, err := s.Hash[idx].WriteTo(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'Hash[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	// KeyAndSignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeyAndSignature.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyAndSignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

func (s *CBnTManifest) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfoCBNT.TotalSize() },
			Value: func() any { return s.StructInfoCBNT },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "Key Manifest Signature Offset",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.KeyManifestSignatureOffset },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &s.Reserved2 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    3,
			Name:  "Revision",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Revision },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "KMSVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.KMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "KMID",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.KMID },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "Pub Key Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.PubKeyHashAlg },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:   7,
			Name: fmt.Sprintf("Hash: Array of \"Key Manifest\" of length %d", len(s.Hash)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				for idx := range s.Hash {
					size += s.Hash[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.Hash },
			Type:  cbnt.ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint16
				err := binary.Read(r, binary.LittleEndian, &count)
				if err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'Hash': %w", err)
				}
				totalN := int64(binary.Size(count))
				s.Hash = make([]Hash, count)
				for idx := range s.Hash {
					n, err := s.Hash[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'Hash[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
		},
		{
			ID:    8,
			Name:  "Key And Signature",
			Size:  func() uint64 { return s.KeyAndSignature.TotalSize() },
			Value: func() any { return &s.KeyAndSignature },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *CBnTManifest) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("CBnTManifest: %v", err)
	}

	return ret, nil
}

func (s *CBnTManifest) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("CBnTManifest: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the Manifest.
func (s *CBnTManifest) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *CBnTManifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	base := s.Common.PrettyString(depth, withHeader, s, "CBnT Key Manifest", opts...)
	var lines []string
	lines = append(lines, base)

	// FIXME: just a temp solution, it is wrong, but low prio for now
	lines = append(lines, pretty.Header(
		depth+1,
		fmt.Sprintf("Hash: Array of \"Key Manifest\" of length %d", len(s.Hash)),
		s.Hash,
	))
	for i := 0; i < len(s.Hash); i++ {
		lines = append(
			lines,
			fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+
				strings.TrimSpace(s.Hash[i].PrettyString(depth+2, true, opts...)),
		)
	}

	return strings.Join(lines, "\n")
}

// Print prints the Key Manifest.
func (m *CBnTManifest) Print() {
	if len(m.KeyAndSignature.Signature.Data) < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
