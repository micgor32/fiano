package cbntbootpolicy

import (
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
)

type (
	// StructInfo is the common header of any element.
	StructInfo = cbnt.StructInfo

	// Manifest is a boot policy manifest
	// TODO: handle as with km
	// PrettyString: Boot Policy Manifest
	Manifest struct {
		// BPMH is the header of the boot policy manifest
		//
		// PrettyString: BPMH: Header
		BPMH `rehashValue:"rehashedBPMH()" json:"bpmHeader"`

		SE   []SE      `json:"bpmSE"`
		TXTE *TXT      `json:"bpmTXTE,omitempty"`
		Res  *Reserved `json:"bpmReserved,omitempty"`

		// PCDE is the platform configuration data element
		//
		// PrettyString: PCDE: Platform Config Data
		PCDE *PCD `json:"bpmPCDE,omitempty"`

		// PME is the platform manufacturer element
		//
		// PrettyString: PME: Platform Manufacturer
		PME *PM `json:"bpmPME,omitempty"`

		// PMSE is the signature element
		//
		// PrettyString: PMSE: Signature
		PMSE Signature `json:"bpmSignature"`
	}

	Reserved struct {
		StructInfo   `id:"__PFRS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
		ReservedData [32]byte `json:"ReservedData"`
	}

	Size4K uint16

	// BPMH is the header of boot policy manifest
	BPMH struct {
		StructInfo `id:"__ACBP__" version:"0x23" var0:"0x20" var1:"uint16(s.TotalSize())"`

		KeySignatureOffset uint16 `json:"bpmhKeySignatureOffset"`

		BPMRevision uint8 `json:"bpmhRevision"`

		// BPMSVN is BPM security version number
		//
		// PrettyString: BPM SVN
		BPMSVN cbnt.SVN `json:"bpmhSNV"`

		// ACMSVNAuth is authorized ACM security version number
		//
		// PrettyString: ACM SVN Auth
		ACMSVNAuth cbnt.SVN `json:"bpmhACMSVN"`

		Reserved0 [1]byte `require:"0" json:"bpmhReserved0,omitempty"`

		NEMDataStack Size4K `json:"bpmhNEMStackSize"`
	}

	// PCD holds various Platform Config Data.
	PCD struct {
		StructInfo `id:"__PCDS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
		Reserved0  [2]byte `json:"pcdReserved0,omitempty"`
		SizeOfData [2]byte `json:"pcdSizeOfData,omitempty"`
		Data       []byte  `json:"pcdData"`
	}

	PM struct {
		StructInfo `id:"__PMDA__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
		Reserved0  [2]byte `require:"0" json:"pcReserved0,omitempty"`
		Data       []byte  `json:"pcData"`
	}

	// IBBSegment defines a single IBB segment
	IBBSegment struct {
		Reserved [2]byte `require:"0" json:"ibbSegReserved"`
		Flags    uint16  `json:"ibbSegFlags"`
		Base     uint32  `json:"ibbSegBase"`
		Size     uint32  `json:"ibbSegSize"`
	}

	// CachingType <TO BE DOCUMENTED>
	CachingType uint8

	// SEFlags <TO BE DOCUMENTED>
	SEFlags uint32

	// SE is an IBB segments element
	//
	// PrettyString: IBB Segments Element
	SE struct {
		StructInfo `id:"__IBBS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
		Reserved0  [1]byte   `require:"0" json:"seReserved0,omitempty"`
		SetNumber  uint8     `require:"0" json:"seSetNumber,omitempty"`
		Reserved1  [1]byte   `require:"0" json:"seReserved1,omitempty"`
		PBETValue  PBETValue `json:"sePBETValue"`
		Flags      SEFlags   `json:"seFlags"`

		// IBBMCHBAR <TO BE DOCUMENTED>
		// PrettyString: IBB MCHBAR
		IBBMCHBAR uint64 `json:"seIBBMCHBAR"`

		// VTdBAR <TO BE DOCUMENTED>
		// PrettyString: VT-d BAR
		VTdBAR uint64 `json:"seVTdBAR"`

		// DMAProtBase0 <TO BE DOCUMENTED>
		// PrettyString: DMA Protection 0 Base Address
		DMAProtBase0 uint32 `json:"seDMAProtBase0"`

		// DMAProtLimit0 <TO BE DOCUMENTED>
		// PrettyString: DMA Protection 0 Limit Address
		DMAProtLimit0 uint32 `json:"seDMAProtLimit0"`

		// DMAProtBase1 <TO BE DOCUMENTED>
		// PrettyString: DMA Protection 1 Base Address
		DMAProtBase1 uint64 `json:"seDMAProtBase1"`

		// DMAProtLimit1 <TO BE DOCUMENTED>
		// PrettyString: DMA Protection 2 Limit Address
		DMAProtLimit1 uint64 `json:"seDMAProtLimit1"`

		PostIBBHash cbnt.HashStructure `json:"sePostIBBHash"`

		IBBEntryPoint uint32 `json:"seIBBEntry"`

		DigestList cbnt.HashList `json:"seDigestList"`

		OBBHash cbnt.HashStructure `json:"seOBBHash"`

		Reserved2 [3]byte `require:"0" json:"seReserved2,omitempty"`

		IBBSegments []IBBSegment `countType:"uint8" json:"seIBBSegments,omitempty"`
	}

	// PBETValue <TO BE DOCUMENTED>
	PBETValue uint8

	Signature struct {
		StructInfo        `id:"__PMSG__" version:"0x20" var0:"0" var1:"0"`
		cbnt.KeySignature `json:"sigKeySignature"`
	}

	// TXT is the TXT element
	TXT struct {
		StructInfo      `id:"__TXTS__" version:"0x21" var0:"0" var1:"uint16(s.TotalSize())"`
		Reserved0       [1]byte          `require:"0" json:"txtReserved0,omitempty"`
		SetNumber       [1]byte          `require:"0" json:"txtSetNumer,omitempty"`
		SInitMinSVNAuth uint8            `default:"0" json:"txtSVN"`
		Reserved1       [1]byte          `require:"0" json:"txtReserved1,omitempty"`
		ControlFlags    TXTControlFlags  `json:"txtFlags"`
		PwrDownInterval Duration16In5Sec `json:"txtPwrDownInterval"`
		// PrettyString: PTT CMOS Offset 0
		PTTCMOSOffset0 uint8 `default:"126" json:"txtPTTCMOSOffset0"`
		// PrettyString: PTT CMOS Offset 1
		PTTCMOSOffset1 uint8   `default:"127" json:"txtPTTCMOSOffset1"`
		ACPIBaseOffset uint16  `default:"0x400" json:"txtACPIBaseOffset,omitempty"`
		Reserved2      [2]byte `json:"txtReserved2,omitempty"`
		// PrettyString: ACPI MMIO Offset
		PwrMBaseOffset uint32        `default:"0xFE000000" json:"txtPwrMBaseOffset,omitempty"`
		DigestList     cbnt.HashList `json:"txtDigestList"`
		Reserved3      [3]byte       `require:"0" json:"txtReserved3,omitempty"`

		SegmentCount uint8 `require:"0" json:"txtSegmentCount,omitempty"`
	}

	Duration16In5Sec      uint16
	TXTControlFlags       uint32
	ExecutionProfile      uint8
	MemoryScrubbingPolicy uint8
	BackupActionPolicy    uint8
	ResetAUXControl       uint8
)
