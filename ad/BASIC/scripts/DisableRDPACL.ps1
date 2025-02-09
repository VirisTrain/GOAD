# Disable RDP access for the user 'alice' using ACL 

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
$group = [ADSI]"WinNT://./Remote Desktop Users,group"
foreach ($member in $group.psbase.Invoke("Members")) {
    $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
    if ($memberName -eq $userToDeny.Split("\")[1]) {
        $group.Remove("WinNT://$userToDeny")
    }
}

