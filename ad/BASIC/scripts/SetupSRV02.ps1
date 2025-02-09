# Create administrator profile
$username = 'Administrator'
$password = ConvertTo-SecureString '$4daDwNIkHYl89ClE_32GV2ivCWnonQQ3tzvs!rmwtM5Pek!siLMje1-DbSVpVPl' -AsPlainText -Force
Start-Job -Credential (New-Object System.Management.Automation.PSCredential ($username, $password)) -ScriptBlock { exit } | Wait-Job


# Add flag.txt
'ctf{another_one_bites_the_dust}' | Out-File -FilePath C:\Users\Administrator\Desktop\flag.txt
