// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

const (
	// StructureIDBPMH is the StructureID (in terms of
	// the document #575623) of element 'BPMH'.
	StructureIDBPMH = "__ACBP__"

	// StructureIDPCD is the StructureID (in terms of
	// the document #575623) of element 'PCD'.
	StructureIDPCD = "__PCDS__"

	// StructureIDPM is the StructureID (in terms of
	// the document #575623) of element 'PM'.
	StructureIDPM = "__PMDA__"

	// StructureIDSE is the StructureID (in terms of
	// the document #575623) of element 'SE'.
	StructureIDSE = "__IBBS__"

	// StructureIDSignature is the StructureID (in terms of
	// the document #575623) of element 'Signature'.
	StructureIDSignature = "__PMSG__"

	// StructureIDTXT is the StructureID (in terms of
	// the document #575623) of element 'TXT'.
	StructureIDTXT = "__TXTS__"
)

const (
	// <TO BE DOCUMENTED>
	CachingTypeWriteProtect = CachingType(iota)
	CachingTypeWriteBack
	CachingTypeReserved0
	CachingTypeReserved1
)

const (
	ExecutionProfileA = ExecutionProfile(iota)
	ExecutionProfileB
	ExecutionProfileC
)

const (
	MemoryScrubbingPolicyDefault = MemoryScrubbingPolicy(iota)
	MemoryScrubbingPolicyBIOS
	MemoryScrubbingPolicySACM
)

const (
	BackupActionPolicyDefault = BackupActionPolicy(iota)
	BackupActionPolicyForceMemoryPowerDown
	BackupActionPolicyForceBtGUnbreakableShutdown
)

const (
	ResetAUXControlResetAUXIndex = ResetAUXControl(iota)
	ResetAUXControlDeleteAUXIndex
)
