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

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type BGManifest struct {
	cbnt.Common
	cbnt.StructInfo `id:"__KEYM__" version:"0x10"`
	KMVersion       uint8              `json:"kmVersion"`
	KMSVN           cbnt.SVN           `json:"kmSVN"`
	KMID            uint8              `json:"kmID"`
	BPKey           cbnt.HashStructure `json:"kmBPKey"`
	KeyAndSignature cbnt.KeySignature  `json:"kmKeySignature"`
}

func (m *BGManifest) SetSignature(
	algo cbnt.Algorithm,
	hashAlgo cbnt.Algorithm, //TODO: change underlying logic to exclude this
	privKey crypto.Signer,
	signedData []byte,
) error {
	// the second use of algo should be gone here
	err := m.KeyAndSignature.SetSignature(algo, algo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}

func (m *BGManifest) ValidateBPMKey(bpmKS cbnt.KeySignature) error {
	h, err := m.BPKey.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash algo %v: %w", m.BPKey.HashAlg, err)
	}

	if len(m.BPKey.HashBuffer) != h.Size() {
		return fmt.Errorf("invalid hash lenght: actual:%d expected:%d", len(m.BPKey.HashBuffer), h.Size())
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

	if !bytes.Equal(m.BPKey.HashBuffer, digest) {
		return fmt.Errorf("BPM key hash does not match the one in KM: actual:%X != in-KM:%X (hash algo: %v)", digest, m.BPKey.HashBuffer, m.BPKey.HashAlg)
	}

	return nil
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *BGManifest) Validate() error {
	// Recursively validating a child structure:
	// if err := s.BPKey.Validate(); err != nil {
	// 	return fmt.Errorf("error on field 'BPKey': %w", err)
	// }
	// Recursively validating a child structure:
	if err := s.KeyAndSignature.Validate(); err != nil {
		return fmt.Errorf("error on field 'KeyAndSignature': %w", err)
	}

	return nil
}

// StructureIDManifest is the StructureID (in terms of
// the document #575623) of element 'Manifest'.
const StructureIDManifest = "__KEYM__"

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BGManifest) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BGManifest) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (s *BGManifest) ReadFrom(r io.Reader) (int64, error) {
	var totalN int64

	err := binary.Read(r, binary.LittleEndian, &s.StructInfo)
	if err != nil {
		return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
	}
	totalN += int64(binary.Size(s.StructInfo))

	n, err := s.ReadDataFrom(r)
	if err != nil {
		return totalN, fmt.Errorf("unable to read data: %w", err)
	}
	totalN += n

	return totalN, nil
}

// ReadDataFrom reads the Manifest from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *BGManifest) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// KMVersion (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMVersion)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMVersion': %w", err)
		}
		totalN += int64(n)
	}

	// KMSVN (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMSVN)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMSVN': %w", err)
		}
		totalN += int64(n)
	}

	// KMID (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.KMID)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KMID': %w", err)
		}
		totalN += int64(n)
	}

	// BPKey (ManifestFieldType: subStruct)
	{
		n, err := s.BPKey.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'BPKey': %w", err)
		}
		totalN += int64(n)
	}

	// KeyAndSignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeyAndSignature.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeyAndSignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *BGManifest) RehashRecursive() {
	s.StructInfo.Rehash()
	s.BPKey.Rehash()
	s.KeyAndSignature.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *BGManifest) Rehash() {
}

// WriteTo writes the Manifest into 'w' in format defined in
// the document #575623.
func (s *BGManifest) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// StructInfo (ManifestFieldType: structInfo)
	{
		n, err := s.StructInfo.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'StructInfo': %w", err)
		}
		totalN += int64(n)
	}

	// KMVersion (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.KMVersion)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KMVersion': %w", err)
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

	// BPKey (ManifestFieldType: subStruct)
	{
		n, err := s.BPKey.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'BPKey': %w", err)
		}
		totalN += int64(n)
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

func (s *BGManifest) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfo.TotalSize(&s.StructInfo) },
			Value: func() any { return &s.StructInfo },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			Name:  "KM Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.KMVersion },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			Name:  "KMSVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.KMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			Name:  "KMID",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.KMID },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			Name:  "BP Key",
			Size:  func() uint64 { return s.BPKey.TotalSize(&s.BPKey) },
			Value: func() any { return &s.BPKey },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			Name:  "Key And Signature",
			Size:  func() uint64 { return s.KeyAndSignature.TotalSize(&s.KeyAndSignature) },
			Value: func() any { return &s.KeyAndSignature },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

// StructInfoSize returns the size in bytes of the value of field StructInfo
func (s *BGManifest) StructInfoTotalSize() uint64 {
	return s.StructInfo.TotalSize(&s.StructInfo)
}

// KMVersionSize returns the size in bytes of the value of field KMVersion
func (s *BGManifest) KMVersionTotalSize() uint64 {
	return 1
}

// KMSVNSize returns the size in bytes of the value of field KMSVN
func (s *BGManifest) KMSVNTotalSize() uint64 {
	return 1
}

// KMIDSize returns the size in bytes of the value of field KMID
func (s *BGManifest) KMIDTotalSize() uint64 {
	return 1
}

// BPKeySize returns the size in bytes of the value of field BPKey
func (s *BGManifest) BPKeyTotalSize() uint64 {
	return s.BPKey.TotalSize(&s.BPKey)
}

// KeyAndSignatureSize returns the size in bytes of the value of field KeyAndSignature
func (s *BGManifest) KeyAndSignatureTotalSize() uint64 {
	return s.KeyAndSignature.TotalSize(&s.KeyAndSignature)
}

// StructInfoOffset returns the offset in bytes of field StructInfo
func (s *BGManifest) StructInfoOffset() uint64 {
	return s.Common.OffsetOf(s, "Struct Info")
}

// KMVersionOffset returns the offset in bytes of field KMVersion
func (s *BGManifest) KMVersionOffset() uint64 {
	return s.Common.OffsetOf(s, "KM Version")
}

// KMSVNOffset returns the offset in bytes of field KMSVN
func (s *BGManifest) KMSVNOffset() uint64 {
	return s.Common.OffsetOf(s, "KMSVN")
}

// KMIDOffset returns the offset in bytes of field KMID
func (s *BGManifest) KMIDOffset() uint64 {
	return s.Common.OffsetOf(s, "KMID")
}

// BPKeyOffset returns the offset in bytes of field BPKey
func (s *BGManifest) BPKeyOffset() uint64 {
	return s.Common.OffsetOf(s, "BP Key")
}

// KeyAndSignatureOffset returns the offset in bytes of field KeyAndSignature
func (s *BGManifest) KeyAndSignatureOffset() uint64 {
	return s.Common.OffsetOf(s, "Key And Signature")
}

// Size returns the total size of the Manifest.
func (s *BGManifest) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *BGManifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "BG Key Manifest", opts...)
}

func (m *BGManifest) Print() {
	if len(m.KeyAndSignature.Signature.Data) < 1 {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --KeyAndSignature--\n\tKey Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
