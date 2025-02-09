# Enable service enum via NETWORK logon
$sid = [Security.Principal.NTAccount]::new('NT AUTHORITY', 'NETWORK').Translate([Security.Principal.SecurityIdentifier])
$sddl = ((sc.exe sdshow scmanager) -join "").Trim()
$sd = ConvertFrom-SddlString -Sddl $sddl
$sd.RawDescriptor.DiscretionaryAcl.AddAccess(
    [Security.AccessControl.AccessControlType]::Allow,
    $sid,
    0x00020015,  # SC_MANAGER_CONNECT | GENERIC_READ
    [Security.AccessControl.InheritanceFlags]::None,
    [Security.AccessControl.PropagationFlags]::None
)
$newSddl = $sd.RawDescriptor.GetSDDLForm('All')
sc.exe sdset scmanager $newSddl


