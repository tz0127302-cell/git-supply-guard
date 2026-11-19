package model

// Stable finding identifiers. docs/CHECKS.md must mention every ID returned
// by AllIDs.
const (
	IDSubRecurse     = "GSG-SUB-001"
	IDSubRelative    = "GSG-SUB-002"
	IDSubProtocol    = "GSG-SUB-003"
	IDSubCredentials = "GSG-SUB-004"
	IDSubUpdateCmd   = "GSG-SUB-005"
	IDSubPath        = "GSG-SUB-006"
	IDSubDuplicate   = "GSG-SUB-007"
	IDSubIgnore      = "GSG-SUB-008"
	IDSubUpdateMerge = "GSG-SUB-009"
	IDSubInventory   = "GSG-SUB-010"
	IDSubNoGitlink   = "GSG-SUB-011"

	IDHookTracked     = "GSG-HOOK-001"
	IDHookHusky       = "GSG-HOOK-002"
	IDHookPathInside  = "GSG-HOOK-003"
	IDHookPathOutside = "GSG-HOOK-004"
	IDHookInstalled   = "GSG-HOOK-005"

	IDCfgCredential  = "GSG-CFG-001"
	IDCfgFileAllow   = "GSG-CFG-002"
	IDCfgFsckOff     = "GSG-CFG-003"
	IDCfgSafeStar    = "GSG-CFG-004"
	IDCfgInsteadOf   = "GSG-CFG-005"
	IDCfgFilter      = "GSG-CFG-006"
	IDCfgAlias       = "GSG-CFG-007"
	IDCfgCommand     = "GSG-CFG-008"
	IDCfgProtocolAny = "GSG-CFG-009"
	IDCfgHTTPHeader  = "GSG-CFG-010"

	IDAttrFilter = "GSG-ATTR-001"
	IDAttrExport = "GSG-ATTR-002"
	IDAttrMerge  = "GSG-ATTR-003"
	IDAttrLFS    = "GSG-ATTR-004"
	IDAttrDiff   = "GSG-ATTR-005"

	IDLinkOutside    = "GSG-LINK-001"
	IDLinkGitMeta    = "GSG-LINK-002"
	IDLinkGitSymlink = "GSG-LINK-003"

	IDModeSpecial  = "GSG-MODE-001"
	IDModeExecMeta = "GSG-MODE-002"

	IDGitlinkOrphan  = "GSG-GITLINK-001"
	IDPathLong       = "GSG-PATH-001"
	IDRefBroad       = "GSG-REF-001"
	IDMergeDriver    = "GSG-MERGE-001"
	IDPatchExternal  = "GSG-PATCH-001"
	IDImportInclude  = "GSG-IMPORT-001"
	IDImportFile     = "GSG-IMPORT-002"
	IDCloneRecursive = "GSG-CLONE-001"
	IDRepoNotGit     = "GSG-REPO-001"
	IDRepoGitfile    = "GSG-REPO-002"
	IDLimit          = "GSG-LIMIT-001"
)

// AllIDs is the catalog order used by documentation tests.
func AllIDs() []string {
	return []string{
		IDSubRecurse,
		IDSubRelative,
		IDSubProtocol,
		IDSubCredentials,
		IDSubUpdateCmd,
		IDSubPath,
		IDSubDuplicate,
		IDSubIgnore,
		IDSubUpdateMerge,
		IDSubInventory,
		IDSubNoGitlink,
		IDHookTracked,
		IDHookHusky,
		IDHookPathInside,
		IDHookPathOutside,
		IDHookInstalled,
		IDCfgCredential,
		IDCfgFileAllow,
		IDCfgFsckOff,
		IDCfgSafeStar,
		IDCfgInsteadOf,
		IDCfgFilter,
		IDCfgAlias,
		IDCfgCommand,
		IDCfgProtocolAny,
		IDCfgHTTPHeader,
		IDAttrFilter,
		IDAttrExport,
		IDAttrMerge,
		IDAttrLFS,
		IDAttrDiff,
		IDLinkOutside,
		IDLinkGitMeta,
		IDLinkGitSymlink,
		IDModeSpecial,
		IDModeExecMeta,
		IDGitlinkOrphan,
		IDPathLong,
		IDRefBroad,
		IDMergeDriver,
		IDPatchExternal,
		IDImportInclude,
		IDImportFile,
		IDCloneRecursive,
		IDRepoNotGit,
		IDRepoGitfile,
		IDLimit,
	}
}
