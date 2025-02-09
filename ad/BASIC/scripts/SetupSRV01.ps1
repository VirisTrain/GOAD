# ----------------------------------------------------
# EnablePSWebAccess.ps1
# ----------------------------------------------------
# PrivCheck
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as an Administrator!"
    Exit
}

# Install Windows PowerShell Web Access feature
try {
    Install-WindowsFeature -Name WindowsPowerShellWebAccess -IncludeManagementTools
    Write-Host "Windows PowerShell Web Access feature installed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to install Windows PowerShell Web Access feature: $_"
    Exit
}

# Install and configure IIS if not already installed
if (!(Get-WindowsFeature Web-Server).Installed) {
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Write-Host "IIS installed successfully." -ForegroundColor Green
}

# Configure PowerShell Web Access gateway
try {
    Install-PswaWebApplication -UseTestCertificate
    Write-Host "PowerShell Web Access gateway configured successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure PowerShell Web Access gateway: $_"
    Exit
}

# Add a rule to allow all users to access all computers
Add-PswaAuthorizationRule -UserName * -ComputerName * -ConfigurationName *

Write-Host "PowerShell Web Access has been enabled and configured." -ForegroundColor Green
Write-Host "Warning: This configuration allows all users to access all computers. Please adjust the authorization rules for your specific security requirements." -ForegroundColor Yellow


# ----------------------------------------------------
# SetupUserProfile.ps1
# ----------------------------------------------------
# Create administrator profile
$username = 'Administrator'
$password = ConvertTo-SecureString 'JIiMqp8$$nerFcfeW_DV_xrFxk8qh2GnYAjhCzNPFvLIh9SPFh3nqcBqeoTZaJPn' -AsPlainText -Force
Start-Job -Credential (New-Object System.Management.Automation.PSCredential ($username, $password)) -ScriptBlock { exit } | Wait-Job

# ----------------------------------------------------
# ProvisionShares.ps1
# ----------------------------------------------------
# Create folders if they don't already exist
mkdir -Force C:\shares
mkdir -Force C:\shares\all
mkdir -Force C:\shares\public
mv -Force C:\administrator.txt C:\shares\all\administrator.txt

# Change file permissions
#$acl = Get-Acl "C:\shares\all\administrator.txt"
#$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","Allow")
#$acl.SetAccessRule($accessRule)
#$acl = Set-Acl "C:\shares\all\administrator.txt"

$path = "C:\shares\all\administrator.txt"
$acl = Get-Acl "C:\shares\all\administrator.txt"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","Allow")
$acl.SetAccessRule($accessRule)
$acl | Set-Acl "C:\shares\all\administrator.txt"
Get-ChildItem -Path "$path" -Recurse -Force | Set-Acl -aclObject $acl -Verbose


# Enable service enum via NETWORK logon
#$sid = [Security.Principal.NTAccount]::new('NT AUTHORITY', 'NETWORK').Translate([Security.Principal.SecurityIdentifier])
#$sddl = ((sc.exe sdshow scmanager) -join "").Trim()
#$sd = ConvertFrom-SddlString -Sddl $sddl
#$sd.RawDescriptor.DiscretionaryAcl.AddAccess(
#    [Security.AccessControl.AccessControlType]::Allow,
#    $sid,
#    0x00020015,  # SC_MANAGER_CONNECT | GENERIC_READ
#    [Security.AccessControl.InheritanceFlags]::None,
#    [Security.AccessControl.PropagationFlags]::None
#)
#$newSddl = $sd.RawDescriptor.GetSDDLForm('All')
#sc.exe sdset scmanager $newSddl


# ----------------------------------------------------
# DisableRDPACL.ps1
# ----------------------------------------------------
# Define the username of the user to be denied RDP access
$userToDeny = "BASIC\alice"  # Replace DOMAIN\Username with the actual username

# Get the current security descriptor of the RDP service
$rdpKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$acl = Get-Acl -Path $rdpKeyPath

# Create a new deny access rule for the specified user
$denyRule = New-Object System.Security.AccessControl.RegistryAccessRule(
    $userToDeny,
    "QueryValues, SetValue, CreateSubKey, EnumerateSubKeys, Notify, Delete",
    "Deny"
)

# Apply the deny rule to the ACL
$acl.SetAccessRule($denyRule)

# Save the modified ACL back to the registry
Set-Acl -Path $rdpKeyPath -AclObject $acl

# Additional measure: Remove the user from the Remote Desktop Users group if they are a member
#$group = [ADSI]"WinNT://./Remote Desktop Users,group"
#foreach ($member in $group.psbase.Invoke("Members")) {
#    $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
#    if ($memberName -eq $userToDeny.Split("\")[1]) {
#        $group.Remove("WinNT://$userToDeny")
#    }
#}


# ----------------------------------------------------
# Add flag.txt
# ----------------------------------------------------
'ctf{reminds_me_of_the_good_old_webshells}' | Out-File -FilePath C:\Users\Administrator\Desktop\flag.txt


# ----------------------------------------------------
# Add charlie credentials
# ----------------------------------------------------
'Charlie, I had to reset your password to FretfulFiddler314 because of the change to our internal password policy at the company. Hope you dont mind. Godspeed!' | Out-File -FilePath C:\Users\Administrator\Desktop\charlie_mail.txt


# ----------------------------------------------------
# UnquotedServicePath.ps1
# ----------------------------------------------------
# Set the path for the folder
$folderPath = 'C:\Program Files\Custom Service1\'
$srcPath = 'C:\Program Files\Service 1.exe'
$dstPath = 'C:\Program Files\Custom Service1\Service 1.exe'
if (-not (Test-Path $folderPath)) {
    mkdir 'C:\Program Files\Custom Service1'
}
Start-Sleep -Seconds 2 # DEBUGGING

# Binary taken from github
#$urlBinary = "https://raw.githubusercontent.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/master/Lab-Setup-Binary/Service%201.exe"  
#Invoke-WebRequest -Uri "$urlBinary" -OutFile "$folderPath\Service 1.exe"
mv "$srcPath" "$dstPath"
Start-Sleep -Seconds 2 # DEBUGGING
icacls "C:\Program Files\Custom Service1" /grant BUILTIN\Users:W
icacls "C:\Program Files\Custom Service1" /grant BASIC\alice:W
New-Service -Name "Custom Service 1" -BinaryPathName "C:\Program Files\Custom Service1\Service 1.exe" -DisplayName "Custom Service 1" -Description "My Custom Service 1" -StartupType Automatic
cmd.exe /c 'sc sdset "Custom Service 1" D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;RPWP;;;BU)'


# ----------------------------------------------------
# AutoLogon.ps1
# ----------------------------------------------------
$Username = 'Administrator'
$Pass = 'JIiMqp8$$nerFcfeW_DV_xrFxk8qh2GnYAjhCzNPFvLIh9SPFh3nqcBqeoTZaJPn'
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$Username" -type String
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$Pass" -type String
Restart-Computer -Force
