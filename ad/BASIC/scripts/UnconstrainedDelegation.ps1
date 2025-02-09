Get-ADComputer -Identity SRV02 | Set-ADAccountControl -TrustedForDelegation $true
