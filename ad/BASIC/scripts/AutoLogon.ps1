$Username = 'Administrator'
$Pass = 'FTvi-dkytNiZR!2PNWNTYj8P$HlOpgqGrQWPnhHLpXT_7VxkHhuh3tp5ibCxdE21'
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$Username" -type String 
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$Pass" -type String
Restart-Computer -Force
