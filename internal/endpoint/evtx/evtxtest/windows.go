package evtxtest

import (
	"fmt"
	"time"
)

// Constructors for the Windows context events the endpoint adapter maps
// (Sysmon 5 and 12-14, Security 4689/4625/4648/4672/4697, PowerShell
// 4103, TaskScheduler 106/140/141/200/201, WMI-Activity 5857-5861). The
// provider names, GUIDs, channels, versions and EventData field order
// follow the manifests of those providers on Windows 10/11 and Server
// 2019/2022, so a fixture looks like what the providers write. They are
// still synthetic: no record was copied from a real host.

const (
	SysmonProvider    = "Microsoft-Windows-Sysmon"
	SysmonGUID        = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
	SysmonChannel     = "Microsoft-Windows-Sysmon/Operational"
	SecurityProvider  = "Microsoft-Windows-Security-Auditing"
	SecurityGUID      = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
	PowerShellProv    = "Microsoft-Windows-PowerShell"
	PowerShellGUID    = "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"
	PowerShellChannel = "Microsoft-Windows-PowerShell/Operational"
	TaskProvider      = "Microsoft-Windows-TaskScheduler"
	TaskGUID          = "{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}"
	TaskChannel       = "Microsoft-Windows-TaskScheduler/Operational"
	WMIProvider       = "Microsoft-Windows-WMI-Activity"
	WMIGUID           = "{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"
	WMIChannel        = "Microsoft-Windows-WMI-Activity/Operational"
	wmiUserDataNS     = "http://manifests.microsoft.com/win/2006/windows/WMI"
)

// Host is the computer name and default user SID stamped on events.
type Host struct {
	Computer string
	UserSID  string
}

func (h Host) base(prov, guid, channel string, id uint16, ver uint8, at time.Time, rec uint64) Event {
	return Event{Provider: prov, ProviderGUID: guid, EventID: id, Qualifiers: -1, Version: ver, Level: 4,
		Time: at, RecordID: rec, PID: 3056, TID: 4012, Channel: channel, Computer: h.Computer, UserSID: h.UserSID}
}

func procGUID(pid uint32) Value {
	return GUID(fmt.Sprintf("{7E2B4F11-%04X-6720-0000-00100000%04X}", pid&0xffff, pid&0xffff))
}

// SysmonProcessTerminated is Sysmon event 5.
func (h Host) SysmonProcessTerminated(rec uint64, at time.Time, pid uint32, image, user string) Event {
	e := h.base(SysmonProvider, SysmonGUID, SysmonChannel, 5, 3, at, rec)
	e.UserSID = "S-1-5-18"
	e.Data = []KV{F("RuleName", String("-")), F("UtcTime", String(at.UTC().Format("2006-01-02 15:04:05.000"))),
		F("ProcessGuid", procGUID(pid)), F("ProcessId", Uint32(pid)), F("Image", String(image)), F("User", String(user))}
	return e
}

// SysmonRegistry is Sysmon event 12 (eventType CreateKey/DeleteKey/
// DeleteValue), 13 (SetValue, extra = Details) or 14 (RenameKey, extra =
// NewName).
func (h Host) SysmonRegistry(rec uint64, id uint16, at time.Time, eventType string, pid uint32, image, target, extra, user string) Event {
	e := h.base(SysmonProvider, SysmonGUID, SysmonChannel, id, 2, at, rec)
	e.UserSID = "S-1-5-18"
	e.Data = []KV{F("RuleName", String("-")), F("EventType", String(eventType)), F("UtcTime", String(at.UTC().Format("2006-01-02 15:04:05.000"))),
		F("ProcessGuid", procGUID(pid)), F("ProcessId", Uint32(pid)), F("Image", String(image)), F("TargetObject", String(target))}
	switch id {
	case 13:
		e.Data = append(e.Data, F("Details", String(extra)))
	case 14:
		e.Data = append(e.Data, F("NewName", String(extra)))
	}
	e.Data = append(e.Data, F("User", String(user)))
	return e
}

func (h Host) security(id uint16, ver uint8, task uint16, at time.Time, rec uint64) Event {
	e := h.base(SecurityProvider, SecurityGUID, "Security", id, ver, at, rec)
	e.Level, e.Task, e.Keywords, e.PID, e.TID, e.UserSID = 0, task, 0x8020000000000000, 4, 120, ""
	return e
}

func subject(sid, user, domain string, logonID uint64) []KV {
	return []KV{F("SubjectUserSid", SID(sid)), F("SubjectUserName", String(user)), F("SubjectDomainName", String(domain)), F("SubjectLogonId", Hex64(logonID))}
}

// Security4689 is "A process has exited".
func (h Host) Security4689(rec uint64, at time.Time, sid, user, domain string, pid uint64, image string, status uint32) Event {
	e := h.security(4689, 0, 13313, at, rec)
	e.Data = append(subject(sid, user, domain, 0x3e7), F("Status", Hex32(status)), F("ProcessId", Hex64(pid)), F("ProcessName", String(image)))
	return e
}

// Security4625 is "An account failed to log on".
func (h Host) Security4625(rec uint64, at time.Time, target, targetDomain string, logonType uint32, ip, workstation string, pid uint64, image string) Event {
	e := h.security(4625, 0, 12544, at, rec)
	e.Keywords = 0x8010000000000000
	e.Data = append(subject("S-1-5-18", "DESK-01$", "WORKGROUP", 0x3e7),
		F("TargetUserSid", SID("S-1-0-0")), F("TargetUserName", String(target)), F("TargetDomainName", String(targetDomain)),
		F("Status", Hex32(0xc000006d)), F("FailureReason", String("%%2313")), F("SubStatus", Hex32(0xc000006a)),
		F("LogonType", Uint32(logonType)), F("LogonProcessName", String("User32 ")), F("AuthenticationPackageName", String("Negotiate")),
		F("WorkstationName", String(workstation)), F("TransmittedServices", String("-")), F("LmPackageName", String("-")), F("KeyLength", Uint32(0)),
		F("ProcessId", Hex64(pid)), F("ProcessName", String(image)), F("IpAddress", String(ip)), F("IpPort", String("0")))
	return e
}

// Security4648 is "A logon was attempted using explicit credentials".
func (h Host) Security4648(rec uint64, at time.Time, sid, user, domain, target, targetDomain, server string, pid uint64, image, ip string) Event {
	e := h.security(4648, 0, 12544, at, rec)
	e.Data = append(subject(sid, user, domain, 0x5c1d2),
		F("LogonGuid", GUID("{00000000-0000-0000-0000-000000000000}")), F("TargetUserName", String(target)), F("TargetDomainName", String(targetDomain)),
		F("TargetLogonGuid", GUID("{00000000-0000-0000-0000-000000000000}")), F("TargetServerName", String(server)), F("TargetInfo", String(server)),
		F("ProcessId", Hex64(pid)), F("ProcessName", String(image)), F("IpAddress", String(ip)), F("IpPort", String("0")))
	return e
}

// Security4672 is "Special privileges assigned to new logon".
func (h Host) Security4672(rec uint64, at time.Time, sid, user, domain, privileges string) Event {
	e := h.security(4672, 0, 12548, at, rec)
	e.Data = append(subject(sid, user, domain, 0x5c1d2), F("PrivilegeList", String(privileges)))
	return e
}

// Security4697 is "A service was installed in the system".
func (h Host) Security4697(rec uint64, at time.Time, sid, user, domain, name, file, account string) Event {
	e := h.security(4697, 0, 12289, at, rec)
	e.Data = append(subject(sid, user, domain, 0x5c1d2), F("ServiceName", String(name)), F("ServiceFileName", String(file)),
		F("ServiceType", Hex32(0x10)), F("ServiceStartType", Uint32(2)), F("ServiceAccount", String(account)))
	return e
}

// PowerShell4103 is a module-logging (pipeline execution) record.
func (h Host) PowerShell4103(rec uint64, at time.Time, pid uint32, command, payload string) Event {
	e := h.base(PowerShellProv, PowerShellGUID, PowerShellChannel, 4103, 1, at, rec)
	e.Task, e.Opcode, e.Keywords, e.PID, e.TID = 106, 20, 0, pid, pid+1
	ctx := "        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.22621.4111\r\n" +
		"        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive\r\n" +
		"        Engine Version = 5.1.22621.4111\r\n        Command Name = " + command + "\r\n        Command Type = Cmdlet\r\n"
	e.Data = []KV{F("ContextInfo", String(ctx)), F("UserData", String("")), F("Payload", String(payload))}
	return e
}

// TaskScheduler is a Task Scheduler Operational event: 106 registered
// (user = UserContext), 140 updated / 141 deleted (user = UserName),
// 200 action started, 201 action completed (action = ActionName).
func (h Host) TaskScheduler(rec uint64, id uint16, at time.Time, task, user, action string, enginePID uint32) Event {
	e := h.base(TaskProvider, TaskGUID, TaskChannel, id, 0, at, rec)
	e.UserSID, e.Keywords = "S-1-5-18", 0x8000000000000000
	inst := GUID("{3B5A1F0C-9E2D-4C8B-A7F6-1D2E3F4A5B6C}")
	switch id {
	case 106:
		e.Data = []KV{F("TaskName", String(task)), F("UserContext", String(user))}
	case 140, 141:
		e.Data = []KV{F("TaskName", String(task)), F("UserName", String(user))}
	case 200:
		e.Data = []KV{F("TaskName", String(task)), F("ActionName", String(action)), F("TaskInstanceId", inst), F("EnginePID", Uint32(enginePID))}
	case 201:
		e.Data = []KV{F("TaskName", String(task)), F("TaskInstanceId", inst), F("ActionName", String(action)), F("ResultCode", Uint32(0)), F("EnginePID", Uint32(enginePID))}
	}
	return e
}

// WMIActivity is a WMI-Activity Operational event; fields are UserData
// (element per event id) in manifest order.
func (h Host) WMIActivity(rec uint64, id uint16, at time.Time, fields ...KV) Event {
	e := h.base(WMIProvider, WMIGUID, WMIChannel, id, 0, at, rec)
	e.Keywords, e.UserSID = 0x4000000000000000, "S-1-5-18"
	e.UserDataElement = map[uint16]string{5857: "Operation_StartedOperational", 5858: "Operation_ClientFailure", 5859: "Operation_EssStarted",
		5860: "Operation_TemporaryEssStarted", 5861: "Operation_ESStoConsumerBinding"}[id]
	e.UserDataNS = wmiUserDataNS
	e.UserData = fields
	return e
}
