// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntkey

import (
	"crypto"
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
	ReadDataFrom(r io.Reader) (int64, error)
	Rehash()
	RehashRecursive()
	WriteTo(w io.Writer) (int64, error)
	TotalSize() uint64
	PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string
	Print()
}

func NewManifest(bgv cbnt.BootGuardVersion) Manifest {
	switch bgv {
	case cbnt.Version10:
		s := &BGManifest{}
		s.StructInfo.Version = 0x10
		copy(s.StructInfo.ID[:], []byte(cbnt.StructureIDManifest))
		s.KeyAndSignature = *cbnt.NewKeySignature()
		s.Rehash()
		return s
	case cbnt.Version20, cbnt.Version21:
		s := &CBnTManifest{}
		s.StructInfo.Version = 0x21
		copy(s.StructInfo.ID[:], []byte(cbnt.StructureIDManifest))
		s.KeyAndSignature = *cbnt.NewKeySignature()
		s.Rehash()
		return s
	default:
		// TODO: let's consider whether it makes sense to return error to the caller
		// here, or whether it is sufficient return nil and let the caller check.
		return nil
	}
}
