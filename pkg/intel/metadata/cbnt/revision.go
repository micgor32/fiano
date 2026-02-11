// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"encoding/binary"
	"fmt"
	"io"
)

var BinaryOrder = binary.LittleEndian

// Well, this can be improved, see comment in cbnt/types.go

func (bgv BootGuardVersion) String() string {
	switch bgv {
	case Version10:
		return "1.0"
	case Version20:
		return "2.0"
	case Version21:
		return "2.1"
	}
	return "unknown"
}

func DetectBGV(r io.ReadSeeker) (BootGuardVersion, error) {
	var s StructInfo
	err := binary.Read(r, BinaryOrder, &s)
	if err != nil {
		return 0, fmt.Errorf("unable to read field 'ID': %w", err)
	}
	_, err = r.Seek(0, 0)
	if err != nil {
		return 0, err
	}

	switch s.Version {
	case 0x10:
		return Version10, nil
	case 0x20:
		fallthrough
	case 0x21:
		return Version20, nil
	case 0x22:
		fallthrough
	case 0x23:
		fallthrough
	case 0x25:
		return Version21, nil
	default:
		return 0, fmt.Errorf("couldn't detect version")
	}
}
