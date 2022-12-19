package lib

type DLPInfo struct {
	DLPPolicy string
	DLPSentiveInfoType string
}


type DeviceConfManagerDetail struct {
	AzureAdJoined string
	EnterpriseJoined string
	DomainJoined string
	WorkplaceJoined string
	IsUserAzureAD string
}

type WindowsSystemInfo struct {
	OSVersion string
	OSEditionID string
	MinorBuild string
	OSProductName string
	OSEditionName string
}


type ServiceStatus struct {
	SenseServiceStatus bool
	UTCServiceStatus bool
	DefenderServiceStatus bool
	WindowsSecurityCenterStatus bool
}


type EndpointStatus struct {
	MDEATPOnboardStatus string
	WindowsDefenderIsServiceRunning string
	WindowsDefenderPassiveModeState string
	WindowsDefenderDisableAntiSpywareStatus string
	WindowsDefenderDisableAntiVirusStatus string
	OrgId string
	TenantId string
	DeviceId string
	EnrollmentStatus string
	ProcessSnapshot []string
	DeviceConfManagerDetails DeviceConfManagerDetail
	WindowsSystemInfos WindowsSystemInfo
	DLPInfos DLPInfo
	ServiceStatus ServiceStatus


}
