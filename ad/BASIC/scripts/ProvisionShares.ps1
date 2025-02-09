# Create folders if they don't already exist
mkdir -Force C:\shares
mkdir -Force C:\shares\all
mkdir -Force C:\shares\public
mv -Force C:\users\administrator\administrator.txt C:\shares\all\administrator.txt

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
