private rule MachO
{
	meta:
		description = "Mach-O binaries"
	condition:
		uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}

rule NativeAPI
{
	meta:
		description = "Native API"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1106/"
		date = "04-12-2020"
		techniques = "Native API"
		tactic = "Execution"
		mitre_att = "T1106"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s0 = "execFile" ascii wide
		$s1 = "NSTask:launch" ascii wide
		$s2 = "popen" ascii wide
		$s3 = "pclose" ascii wide
		$s4 = "pthread_create" ascii wide
	condition:
		MachO and (any of them)
}


rule IngressToolTransfer
{
	meta:
		description = "Ingress Tool Transfer"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1105/"
		date = "04-12-2020"
		techniques = "Ingress Tool Transfer"
		tactic = "Command And Control"
		mitre_att = "T1113"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$hex1 = { 20 72 73 79 6e 63 20 } // rsync
		$hex2 = { 20 73 63 70 20 } // scp
		$hex3 = { 20 73 66 74 70 20 } // sftp
		$hex4 = { 46 54 50 4d 61 6e 61 67 65 72 } // FTPManager
	condition:
		any of them
}


rule ScreenCapture
{
	meta:
		description = "Screen Capture"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1113/"
		date = "04-12-2020"
		techniques = "Screen Capture"
		tactic = "Collection"
		mitre_att = "T1113"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "CGGetActiveDisplayList" ascii wide
		$s2 = "CGDisplayCreateImage" ascii wide
	condition:
		all of them
}

rule PrivilegeEscalation
{
	meta:
		description = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1548/003/"
		date = "04-12-2020"
		techniques = "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"
		tactic = "Privilege Escalation, Defense Evasion"
		mitre_att = "T1548.003"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$hex = { 20 73 75 64 6f 20 }
	condition:
		any of them
}

rule DeobfuscateDecode
{
	meta:
		description = "Deobfuscate/Decode Files or Information"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1140/"
		date = "04-12-2020"
		techniques = "Deobfuscate/Decode Files or Information"
		tactic = "Defense Evasion"
		mitre_att = "T1140"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "CCCrypt" ascii wide nocase
  	$s2 = "CommonCrypto" ascii wide nocase
	condition:
		any of them
}

rule ProcessInjection
{
	meta:
		description = "Process Injection: Ptrace System Calls"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1055/008/"
		date = "04-12-2020"
		techniques = "Process Injection: Ptrace System Calls"
		tactic = "Defense Evasion, Privilege Escalation"
		mitre_att = "T1055.008"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "ptrace" ascii wide
	condition:
		MachO and (any of them)
}
rule SystemInformationDiscovery
{
	meta:
		description = "System Information Discovery"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1082/"
		date = "04-12-2020"
		techniques = "System Information Discovery"
		tactic = "Discovery"
		mitre_att = "T1082"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "system_profiler" ascii wide
  	$s2 = "/usr/sbin/ioreg" ascii wide
	condition:
		any of them
}
rule VirtualizationSandboxEvasion
{
	meta:
		description = "Virtualization/Sandbox Evasion"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1497/"
		date = "04-12-2020"
		techniques = "Virtualization/Sandbox Evasion"
		tactic = "Defense Evasion, Discovery"
		mitre_att = "T1497"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "_sleep" ascii wide
	condition:
		not uint16(0) == 0x5a4d and any of them
}
rule PermissionsModification
{
	meta:
		description = "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1222/002/"
		date = "04-12-2020"
		techniques = "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"
		tactic = "Defense Evasion"
		mitre_att = "T1222.002"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "chown" ascii wide
  	$s2 = "chmod" ascii wide
	condition:
		not uint16(0) == 0x5a4d and any of them
}
rule WebProtocols
{
	meta:
		description = "Application Layer Protocol: Web Protocols"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1071/001/"
		date = "04-12-2020"
		techniques = "Application Layer Protocol: Web Protocols"
		tactic = "Command And Control"
		mitre_att = "T1071.001"
		sharing = "TLP:WHITE"
		score = 50
	strings:
	  $s1 = "libcurl" ascii wide
	  $s2 = "curl" ascii wide
	  $hex = { 20 77 67 65 74 20 } //wget
	condition:
		not uint16(0) == 0x5a4d and any of them
}
rule Launchctl
{
	meta:
		description = "System Services: Launchctl"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1569/001/"
		date = "04-12-2020"
		techniques = "System Services: Launchctl"
		tactic = "Execution"
		mitre_att = "T1569.001"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "launchctl" ascii wide
	condition:
		any of them
}
rule ScheduledTaskJobCron
{
	meta:
		description = "Scheduled Task/Job: Cron"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1053/003/"
		date = "04-12-2020"
		techniques = "Scheduled Task/Job: Cron"
		tactic = "Execution, Persistence, Privilege Escalation"
		mitre_att = "T1053.003"
		sharing = "TLP:WHITE"
		score = 50
	strings:
  	$s1 = "crontab" ascii wide
	condition:
		any of them
}
rule StartupItems
{
	meta:
		description = "Boot or Logon Initialization Scripts: Startup Items"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1037/005/"
		date = "04-12-2020"
		techniques = "Boot or Logon Initialization Scripts: Startup Items"
		tactic = "Persistence, Privilege Escalation"
		mitre_att = "T1037.005"
		sharing = "TLP:WHITE"
		score = 50
	strings:
		$s1 = "/Library/StartupItems" ascii wide
  	$s2 = "StartupParameters.plist" ascii wide
	condition:
		any of them
}
rule LogonScript
{
	meta:
		description = "Boot or Logon Initialization Scripts: Logon Script (Mac)"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1037/002/"
		date = "04-12-2020"
		techniques = "Boot or Logon Initialization Scripts: Logon Script (Mac)"
		tactic = "Persistence, Privilege Escalation"
		mitre_att = "T1037.002"
		sharing = "TLP:WHITE"
		score = 50
	strings:
		$s1 = "com.apple.backgroundtaskmanagementagent/backgrounditems.btm" ascii wide
	condition:
		all of them
}
rule LaunchDaemons
{
	meta:
		description = "Create or Modify System Process: Launch Daemon"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1543/004/"
		date = "04-12-2020"
		techniques = "Create or Modify System Process: Launch Daemon"
		tactic = "Persistence, Privilege Escalation"
		mitre_att = "T1543.004"
		sharing = "TLP:WHITE"
		score = 50
	strings:
		$s1 = "/Library/LaunchDaemons" ascii wide
	condition:
		all of them
}
rule LaunchAgents
{
	meta:
		description = "Create or Modify System Process: Launch Agent"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1543/001/"
		date = "04-12-2020"
		techniques = "Create or Modify System Process: Launch Agent"
		tactic = "Persistence, Privilege Escalation"
		mitre_att = "T1543.001"
		sharing = "TLP:WHITE"
		score = 50
	strings:
		$s1 = "/Library/LaunchAgents" ascii wide
	condition:
		all of them
}
rule Scripting_Python
{
	meta:
		description = "Command and Scripting Interpreter: Python"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1059/006/"
		date = "04-12-2020"
		techniques = "Command and Scripting Interpreter: Python"
		tactic = "Execution"
		mitre_att = "T1059.006"
		sharing = "TLP:WHITE"
		score = 50
	strings:
		$s1 = "/usr/bin/python" ascii wide nocase
		$s2 = "/System/Library/Frameworks/Python.framework/Versions/2.7/" ascii wide nocase
		$hex = { 70 79 74 68 6f 6e 20 }
	condition:
		not uint16(0) == 0x5a4d and any of them
}
rule Scripting_UnixShell
{
	meta:
		description = "Command and Scripting Interpreter: Unix Shell"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1059/004/"
		date = "04-12-2020"
		techniques = "Command and Scripting Interpreter: Unix Shell"
		tactic = "Execution"
		mitre_att = "T1059.004"
		sharing = "TLP:WHITE"
		score = 50
	strings:
		$s1 = "/bin/bash" ascii wide
		$s2 = "/bin/zsh" ascii wide
		$hex = { 2f 62 69 6e 2f 73 68 20 }
	condition:
		any of them
}
rule Scripting_AppleScript
{
	meta:
		description = "Command and Scripting Interpreter: AppleScript"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1059/002/"
		date = "04-12-2020"
		techniques = "Command and Scripting Interpreter: AppleScript"
		tactic = "Execution"
		mitre_att = "T1059.002"
		sharing = "TLP:WHITE"
		score = 50
	strings:
    $s1 = "#!/usr/bin/osascript" ascii wide
    $s2 = "osascript" ascii wide
  condition:
    any of them
}
rule SystemOwnerUserDiscovery
{
	meta:
		description = "System Owner/User Discovery"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1033/"
		date = "04-12-2020"
		techniques = "System Owner/User Discovery"
		tactic = "Discovery"
		mitre_att = "T1033"
		sharing = "TLP:WHITE"
		score = 50
	strings:
    $s1 = "whoami" ascii wide
  condition:
    not uint16(0) == 0x5a4d and any of them
}
rule ProcessDiscovery
{
	meta:
		description = "Process Discovery"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1057/"
		date = "04-12-2020"
		techniques = "Process Discovery"
		tactic = "Discovery"
		mitre_att = "T1057"
		sharing = "TLP:WHITE"
		score = 50
	strings:
    $s1 = "ps aux" ascii wide
		$s2 = "ps -ef | grep" ascii wide
  condition:
    any of them
}
rule SystemNetworkConnectionsDiscovery
{
	meta:
		description = "System Network Connections Discovery"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1049/"
		date = "04-12-2020"
		techniques = "System Network Connections Discovery"
		tactic = "Discovery"
		mitre_att = "T1049"
		sharing = "TLP:WHITE"
		score = 50
	strings:
    $s1 = "netstat" ascii wide
		$s2 = "/usr/sbin/lsof" ascii wide
  condition:
    not uint16(0) == 0x5a4d and any of them
}
rule AccountDiscoveryLocalAccount
{
	meta:
		description = "Account Discovery: Local Account"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1087/001/"
		date = "04-12-2020"
		techniques = "Account Discovery: Local Account"
		tactic = "Discovery"
		mitre_att = "T1087.001"
		sharing = "TLP:WHITE"
		score = 50
	strings:
    $s1 = "/usr/bin/id" ascii wide
		$s2 = "/usr/bin/groups" ascii wide
		$s3 = "/etc/passwd" ascii wide
  condition:
    any of them
}
rule PermissionGroupsDiscoveryLocalGroups
{
	meta:
		description = "Permission Groups Discovery: Local Groups"
		author = "Jesper Mikkelsen"
		reference = "https://attack.mitre.org/techniques/T1069/001/"
		date = "04-12-2020"
		techniques = "Permission Groups Discovery: Local Groups"
		tactic = "Discovery"
		mitre_att = "T1069.001"
		sharing = "TLP:WHITE"
		score = 50
	strings:
    $s1 = "dscl . -list" ascii wide
  condition:
    any of them
}
