// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntkey

import (
	"crypto"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type Manifest interface {
	ValidateBPMKey(bpmKS cbnt.KeySignature) error
	SetSignature(
		algo cbnt.Algorithm,
		hashAlgo cbnt.Algorithm,
		privKey crypto.Signer,
		signedData []byte,
	) error
	Validate() error
	GetStructInfo() cbnt.StructInfo
	SetStructInfo(newStructInfo cbnt.StructInfo)
	ReadFrom(r io.Reader) (int64, error)
	WriteTo(w io.Writer) (int64, error)
	SizeOf(id int) (uint64, error)
	OffsetOf(id int) (uint64, error)
	Layout() []cbnt.LayoutField
	TotalSize() uint64
	PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
	Print()
}

func NewManifest(bgv cbnt.BootGuardVersion) (Manifest, error) {
	switch bgv {
	case cbnt.Version10:
		s := &BGManifest{}
		s.StructInfoBG = *cbnt.NewStructInfo(cbnt.Version10).(*cbnt.StructInfoBG)
		s.StructInfoBG.Version = 0x10
		copy(s.StructInfoBG.ID[:], []byte(cbnt.StructureIDManifest))
		s.KeyAndSignature = *cbnt.NewKeySignature()
		return s, nil
	case cbnt.Version20, cbnt.Version21:
		s := &CBnTManifest{}
		s.StructInfoCBNT = *cbnt.NewStructInfo(cbnt.Version20).(*cbnt.StructInfoCBNT)
		s.StructInfoCBNT.Version = 0x21
		copy(s.StructInfoCBNT.ID[:], []byte(cbnt.StructureIDManifest))
		s.KeyAndSignature = *cbnt.NewKeySignature()
		return s, nil
	default:
		// This will never be the case in internal usage of NewManifest,
		// though out of principle the error handling is here
		return nil, fmt.Errorf("version not supported")
	}
}
