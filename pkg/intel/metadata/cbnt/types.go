// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package cbnt

import (
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// All custom types definitions for the metadata pkg that are shared
// and/or duplicated (for e.g. used both in bg and cbnt packages wo.
// any modifications)
type (
	// FIXME: we could stick to having only 1.0 and 2.0, and treat
	// "2.1" as 2.0. After all the, in the "hacky" temp fix, the logic
	// of handling the header is the same (afaik Intel didn't changed
	// anything there), and we only have to treat headers from 21 to 25
	// as 20.
	BootGuardVersion uint8

	// StructureID is the magic ID string used to identify the structure type
	// in the manifest
	StructureID [8]byte
	SVN         uint8
	Algorithm   uint16
	BitSize     uint16

	StructInfo struct {
		Common
		ID          StructureID `json:"StructInfoID"`
		Version     uint8       `json:"StructInfoVersion"`
		Variable0   uint8       `json:"StructInfoVariable0"`
		ElementSize uint16      `json:"StructInfoElementSize"`
	}

	ManifestFieldType string

	LayoutField struct {
		ID    int
		Name  string
		Size  func() uint64
		Value func() any
		Type  ManifestFieldType
		// optional list reader onluy to be used for types that contain
		// ManifestFieldList
		ReadList func(r io.Reader) (int64, error)
	}

	LayoutProvider interface {
		Layout() []LayoutField
	}

	// Stateless engine, we use as "accessor" to offset and size
	// values per structure instead of dedicated methods.
	// TODO: mention in docs how to work with it since all the
	// <type>TotalSize etc. is gone now. It wasn't used that much
	// externally but anyways :D
	Common struct{}

	// Structure is an abstraction of a structure of a manifest.
	Structure interface {
		io.ReaderFrom
		io.WriterTo
		TotalSize() uint64
		// PrettyString returns the whole object as a structured string.
		PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
	}

	// Element is an abstraction of an element of a manifest.
	Element interface {
		Structure
		ReadDataFrom(r io.Reader) (int64, error)
		GetStructInfo() StructInfo
		SetStructInfo(StructInfo)
	}

	// ElementsContainer is an abstraction of set of elements of a manifest (for
	// example: the root structure of BPM).
	ElementsContainer interface {
		Structure
		GetFieldByStructID(structID string) any
	}

	Manifest interface {
		Structure
	}

	HashStructure struct {
		Common
		HashAlg    Algorithm `default:"0x10" json:"hsAlg"`
		HashBuffer []byte    `json:"hsBuffer"`
	}

	// HashList describes multiple digests
	HashList struct {
		Common
		Size uint16          `rehashValue:"TotalSize()" json:"hlSize"`
		List []HashStructure `json:"hlList"`
	}

	Signature struct {
		Common
		SigScheme Algorithm `json:"sigScheme"`
		Version   uint8     `require:"0x10" json:"sigVersion,omitempty"`
		KeySize   BitSize   `json:"sigKeysize,omitempty"`
		HashAlg   Algorithm `json:"sigHashAlg"`
		Data      []byte    `countValue:"KeySize.InBytes()" prettyValue:"dataPrettyValue()" json:"sigData"`
	}

	KeySignature struct {
		Common
		Version   uint8     `require:"0x10" json:"ksVersion,omitempty"`
		Key       Key       `json:"ksKey"`
		Signature Signature `json:"ksSignature"`
	}

	Key struct {
		Common
		KeyAlg  Algorithm `json:"keyAlg"`
		Version uint8     `require:"0x10"  json:"keyVersion"`
		KeySize BitSize   `json:"keyBitsize"`
		Data    []byte    `countValue:"keyDataSize()" json:"keyData"`
	}

	// ChipsetACModuleInformation represents Chipset AC Module Information Table parts for all versions
	ChipsetACModuleInformation struct {
		Common
		UUID            [16]byte
		ChipsetACMType  uint8
		Version         uint8
		Length          uint16
		ChipsetIDList   uint32
		OsSinitDataVer  uint32
		MinMleHeaderVer uint32
		Capabilities    uint32
		AcmVersion      uint8
		AcmRevision     [3]uint8
		ProcessorIDList uint32
	}

	// ChipsetACModuleInformationV5 represents Chipset AC Module Information Table for version >= 5
	ChipsetACModuleInformationV5 struct {
		Common
		Base        ChipsetACModuleInformation
		TPMInfoList uint32
	}

	// TPM2PCRExtendPolicySupport defined TPM2 PCR Extend policy support.
	TPM2PCRExtendPolicySupport uint8

	// TPMFamilySupport defines TPM family support
	TPMFamilySupport uint8

	// TPMCapabilities defines TPM capabilities
	TPMCapabilities uint32

	// TPMInfoList represents TPM capabilities supported by ACM
	TPMInfoList struct {
		Common
		Capabilities TPMCapabilities
		Algorithms   []Algorithm
	}
)
