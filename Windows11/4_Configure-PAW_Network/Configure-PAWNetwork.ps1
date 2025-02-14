# Check if Hyper-v is installed
if((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-v).State -ne "Enabled")
{
    Write-Warning "Hyper-V is not enabled, will exit"
    Exit 1
}

# Create VMSwitch for External access
$NetAdapter = Get-NetAdapter -Physical | Where-Object Status -EQ Up
New-VMSwitch -Name "UplinkSwitch" -NetAdapterName $NetAdapter.Name -AllowManagementOS $true

# Verify the switch
if((Get-VMSwitch | Where-Object Name -EQ UplinkSwitch).Count -ne 1)
{
    Write-Warning "The VMSwitch UplinkSwitch was not created, exit"
    Exit 1
}

Get-NetAdapter -Name "*default switch*" | Disable-NetAdapter -Confirm:$false