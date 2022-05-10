# Enable RDP
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Force
Get-NetFirewallRule -Group "@FirewallAPI.dll,-28752" | Enable-NetFirewallRule