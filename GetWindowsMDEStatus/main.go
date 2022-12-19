package main

import (
	"GetWindowsMDEStatus/lib"
	"encoding/json"
	"fmt"
)

func InitMDEStatus() lib.EndpointStatus{
	//获取mde相关的进程
	var model lib.EndpointStatus
	_, result1 := lib.GetMDEProcessEx()
	fmt.Println("mde process", result1)
	model.ProcessSnapshot = result1

	//获取MDE的设备 aad状态
	result2 := lib.GetDsRegStatus()
	fmt.Println(result2)
	model.DeviceConfManagerDetails.AzureAdJoined = result2["AzureAdJoined"]
	model.DeviceConfManagerDetails.EnterpriseJoined = result2["EnterpriseJoined"]
	model.DeviceConfManagerDetails.DomainJoined = result2["DomainJoined"]
	model.DeviceConfManagerDetails.IsUserAzureAD = result2["IsUserAzureAD"]
	model.DeviceConfManagerDetails.WorkplaceJoined = result2["WorkplaceJoined"]
	//获取onboard状态
	model.MDEATPOnboardStatus, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status",
		"OnboardingState")
	fmt.Println(model.MDEATPOnboardStatus)
	// 获取WindowsDefenderIsServiceRunning
	model.WindowsDefenderIsServiceRunning, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows Defender",
		"IsServiceRunning")
	fmt.Println(model.WindowsDefenderIsServiceRunning)
	//
	model.WindowsDefenderDisableAntiSpywareStatus, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows Defender",
		"DisableAntiSpyware")

	//
	model.WindowsDefenderDisableAntiVirusStatus, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows Defender",
		"DisableAntiVirus")


	// 获取MDE service的状态
	serviceStatus := lib.ServiceStatus{
		SenseServiceStatus:          lib.GetServiceStatus("sense"),
		UTCServiceStatus:            lib.GetServiceStatus("diagtrack"),
		DefenderServiceStatus:       lib.GetServiceStatus("windefend"),
		WindowsSecurityCenterStatus: lib.GetServiceStatus("wscsvc"),
	}
	model.ServiceStatus = serviceStatus

	//获取windows defender是否处于passive mode的状态
	model.WindowsDefenderPassiveModeState, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows Defender",
		"PassiveMode")

	fmt.Println(model.WindowsDefenderPassiveModeState)


	//获取OrgId
	model.OrgId, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status",
		"OrgID")


	//获取WindowsSystemInfo
	windowsSystemInfo := lib.WindowsSystemInfo{}
	windowsSystemInfo.MinorBuild, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","UBR")
	windowsSystemInfo.OSEditionID, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","EditionID")
	windowsSystemInfo.OSProductName, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","ProductName")
	windowsSystemInfo.OSEditionName, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","InstallationType")

	model.WindowsSystemInfos = windowsSystemInfo

	//decode dlppolicy
	dlp := lib.DLPInfo{}
	dlpPolicy, _ := lib.GetRegistryValueAsBinaryDecode("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection", "dlpPolicy")

	dlp.DLPPolicy = dlpPolicy
	fmt.Println(dlpPolicy)

	//decode dlpsentypeinfo(暂时先不要取)
	//dlpSensetiveInfo, _ := lib.GetRegistryValueAsBinaryDecode("SOFTWARE\\Microsoft\\Windows Advanced Threat Protection", "dlpSensitiveInfoTypesPolicy")
	//dlp.DLPSentiveInfoType = string(dlpSensetiveInfo)
	//fmt.Println(string(dlpSensetiveInfo))

	model.DLPInfos = dlp

	//OrgId
	model.OrgId, _ = lib.GetSettingsFromRegistry("SOFTWARE\\\\Microsoft\\\\Windows Advanced Threat Protection\\Status","OrgID")
	model.TenantId, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\SenseCM","TenantId")
	model.DeviceId, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\SenseCM","DeviceId")
	model.EnrollmentStatus, _ = lib.GetSettingsFromRegistry("SOFTWARE\\Microsoft\\SenseCM","EnrollmentStatus")

	return model
}


func main(){
	data := InitMDEStatus()
	jsonData, _ := json.Marshal(data)
	fmt.Println("=========================")
	fmt.Println(string(jsonData))
}
