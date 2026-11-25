<#
.SYNOPSIS
    Displays, filters and deletes PAWDeploy logs.
.NOTES
    Version : 2.0.0.2
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding()]
param(
    [int]$WindowX,
    [int]$WindowY,
    [string]$LogFolder,
    [switch]$CreateOnly
)
$ErrorActionPreference = 'Stop'
$script:PAWEdition = 'Community'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
Import-Module (Join-Path $root 'Functions\PAWUIUtility\PAWUIUtility.psd1') -ErrorAction Stop
Add-Type -AssemblyName System.Windows.Forms
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath
if (-not $PSBoundParameters.ContainsKey('LogFolder')) {
    if ([string]::IsNullOrWhiteSpace($env:TEMP)) { throw 'TEMP is not set; unable to locate PAWDeploy logs.' }
    $LogFolder = Join-Path $env:TEMP 'PAWDeploy'
}

$form = New-Object Windows.Forms.Form
$form.Text = $script:PAWToolTitle
$form.Size = New-Object Drawing.Size(1344, 756)
$form.MinimumSize = $form.Size
$form.StartPosition = 'CenterScreen'
if ($PSBoundParameters.ContainsKey('WindowX') -and $PSBoundParameters.ContainsKey('WindowY')) {
    $form.StartPosition = 'Manual'
    $form.Location = New-Object Drawing.Point($WindowX, $WindowY)
}
$form.Font = New-Object Drawing.Font('Segoe UI', 10)
$form.Add_Disposed({ param($sender, $eventArgs) $sender.Font.Dispose() })
$form.Icon = Get-PAWWindowIcon
$form.Add_Disposed({ param($sender, $eventArgs) $sender.Icon.Dispose() })

$logLabel = New-PAWUiLabel -Text 'Log files' -X 20 -Y 82
$list = New-Object Windows.Forms.ListBox
$list.Name = 'LogFiles'; $list.DisplayMember = 'Name'
$list.Location = New-Object Drawing.Point(20, 112)
$list.Size = New-Object Drawing.Size(280, 505)
$list.Anchor = 'Top, Bottom, Left'
$list.IntegralHeight = $false
$list.HorizontalScrollbar = $true

$levelLabel = New-PAWUiLabel -Text 'Level' -X 320 -Y 82
$level = New-Object Windows.Forms.ComboBox
$level.Name = 'Level'; $level.DropDownStyle = 'DropDownList'
$level.Location = New-Object Drawing.Point(320, 112); $level.Width = 110
$null = $level.Items.AddRange(@('All', 'INFO', 'WARN', 'ERROR'))
$level.SelectedIndex = 0
$sinceLabel = New-PAWUiLabel -Text 'From date' -X 445 -Y 82
$since = New-Object Windows.Forms.DateTimePicker
$since.Name = 'Since'; $since.Format = 'Short'; $since.ShowCheckBox = $true; $since.Checked = $false
$since.Location = New-Object Drawing.Point(445, 112); $since.Width = 135
$untilLabel = New-PAWUiLabel -Text 'Through date' -X 595 -Y 82
$until = New-Object Windows.Forms.DateTimePicker
$until.Name = 'Until'; $until.Format = 'Short'; $until.ShowCheckBox = $true; $until.Checked = $false
$until.Location = New-Object Drawing.Point(595, 112); $until.Width = 135
$searchLabel = New-PAWUiLabel -Text 'Search text' -X 745 -Y 82
$search = New-Object Windows.Forms.TextBox
$search.Name = 'Search'; $search.Location = New-Object Drawing.Point(745, 112); $search.Width = 250
$apply = New-PAWUiButton -Text 'Apply filters' -X 1010 -Y 109 -Width 140 -Height 30 -Accent
$apply.Name = 'ApplyFilters'
$auto = New-Object Windows.Forms.CheckBox
$auto.Name = 'AutoRefresh'; $auto.Text = 'Auto refresh (5 s)'; $auto.AutoSize = $true
$auto.Location = New-Object Drawing.Point(880, 640)
$auto.Anchor = 'Bottom, Left'

$content = New-Object Windows.Forms.TextBox
$content.Name = 'LogContent'; $content.Multiline = $true; $content.ReadOnly = $true
$content.ScrollBars = 'Both'; $content.WordWrap = $false
$content.Location = New-Object Drawing.Point(320, 155)
$content.Size = New-Object Drawing.Size(990, 462)
$content.Anchor = 'Top, Bottom, Left, Right'
$content.Font = New-Object Drawing.Font('Consolas', 10)
$content.Add_Disposed({ param($sender, $eventArgs) $sender.Font.Dispose() })
$refresh = New-PAWUiButton -Text 'Refresh' -X 20 -Y 635 -Width 135 -Height 30
$refresh.Name = 'RefreshLogs'; $refresh.Anchor = 'Bottom, Left'
$delete = New-PAWUiButton -Text 'Delete log' -X 230 -Y 635
$delete.Name = 'DeleteLog'; $delete.Anchor = 'Bottom, Left'
$deleteAll = New-PAWUiButton -Text 'Delete all logs' -X 440 -Y 635
$deleteAll.Name = 'DeleteAllLogs'; $deleteAll.Anchor = 'Bottom, Left'
$copy = New-PAWUiButton -Text 'Copy selection' -X 650 -Y 635 -Width 160 -Height 30
$copy.Name = 'CopyLog'; $copy.Anchor = 'Bottom, Left'
$status = New-PAWUiLabel -Text '' -X 20 -Y 675
$status.Name = 'LogStatus'; $status.AutoSize = $false; $status.Width = 1290; $status.Height = 30
$status.Anchor = 'Bottom, Left, Right'
$close = New-PAWUiButton -Text 'Close'
$close.Tag = $form
$close.Add_Click({ param($sender, $eventArgs) $sender.Tag.Close() })

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 5000
$state = @{
    Form = $form; List = $list; Level = $level; Since = $since; Until = $until
    Search = $search; Content = $content; Status = $status; Auto = $auto; Timer = $timer
    Command = (Join-Path $PSScriptRoot 'Get-PAWLogs.ps1'); LogFolder = $LogFolder
    Loading = $false; RefreshError = $null; LoadError = $null
}
$state.Load = {
    param($s)
    if ($s.Loading -or $null -eq $s.List.SelectedItem) { return }
    $s.LoadError = $null
    try {
        $parameters = @{ Name = $s.List.SelectedItem.Name; LogFolder = $s.LogFolder; Tail = 1000; NoTitle = $true }
        if ($s.Level.SelectedItem -ne 'All') { $parameters.Level = [string]$s.Level.SelectedItem }
        if ($s.Since.Checked) { $parameters.Since = $s.Since.Value.Date }
        if ($s.Until.Checked) { $parameters.Until = $s.Until.Value.Date.AddDays(1).AddTicks(-1) }
        if ($s.Search.Text.Length) { $parameters.Text = $s.Search.Text }
        $entries = @(& $s.Command @parameters)
        $text = ($entries | ForEach-Object RawText) -join [Environment]::NewLine
        if ($s.Content.Text -cne $text) {
            $start = $s.Content.SelectionStart
            $length = $s.Content.SelectionLength
            $s.Content.Text = $text
            $s.Content.Select([Math]::Min($start, $text.Length), [Math]::Min($length, [Math]::Max(0, $text.Length - $start)))
        }
        $s.Status.Text = "Showing $($entries.Count) matching entries (latest 1000 maximum)."
    }
    catch {
        $s.LoadError = $_.Exception.Message
        $s.Status.Text = "Unable to read log: $($s.LoadError)"
    }
}
$state.Refresh = {
    param($s)
    $s.RefreshError = $null
    $s.LoadError = $null
    try {
        $previous = if ($null -ne $s.List.SelectedItem) { $s.List.SelectedItem.Name } else { $null }
        $files = @(& $s.Command -LogFolder $s.LogFolder -NoTitle)
        $s.Loading = $true
        $s.List.BeginUpdate()
        try {
            $s.List.Items.Clear()
            foreach ($file in $files) { $null = $s.List.Items.Add($file) }
            $selected = -1
            for ($i = 0; $i -lt $files.Count; $i++) {
                if ($files[$i].Name -eq $previous) { $selected = $i; break }
            }
            if ($selected -lt 0 -and $files.Count) { $selected = 0 }
            $s.List.SelectedIndex = $selected
        }
        finally { $s.List.EndUpdate(); $s.Loading = $false }
        if ($files.Count) { & $s.Load $s }
        else { $s.Content.Clear(); $s.Status.Text = "No .log files found in $($s.LogFolder)." }
    }
    catch {
        $s.Loading = $false
        $s.RefreshError = $_.Exception.Message
        $s.Status.Text = "Unable to list logs: $($s.RefreshError)"
    }
}
$state.ConfirmDelete = {
    param($s, $message)
    [Windows.Forms.MessageBox]::Show($s.Form, $message, 'Delete logs', 'YesNo', 'Warning', 'Button2')
}
$state.ReportDeleteError = {
    param($s, $message)
    [void][Windows.Forms.MessageBox]::Show($s.Form, $message, 'Delete logs failed', 'OK', 'Error')
}
$state.Delete = {
    param($s, [bool]$all)
    try {
        if ($all) {
            $files = @(& $s.Command -LogFolder $s.LogFolder -NoTitle)
            if (-not $files.Count) { $s.Status.Text = 'There are no logs to delete.'; return }
            $message = "Delete all $($files.Count) .log files in '$($s.LogFolder)'? This cannot be undone."
        }
        else {
            if ($null -eq $s.List.SelectedItem) { $s.Status.Text = 'Select a log to delete.'; return }
            $files = @($s.List.SelectedItem)
            $message = "Delete log '$($files[0].Name)'? This cannot be undone."
        }
        if ((& $s.ConfirmDelete $s $message) -ne [Windows.Forms.DialogResult]::Yes) { return }
        $failures = @()
        $deleted = 0
        foreach ($file in $files) {
            try {
                Remove-Item -LiteralPath $file.Path -Force -ErrorAction Stop
                $deleted++
            }
            catch { $failures += "$($file.Name): $($_.Exception.Message)" }
        }
        & $s.Refresh $s
        $result = if ($failures.Count) {
            "Deleted $deleted of $($files.Count) logs. Unable to delete: $($failures -join '; ')"
        } else { "Deleted $deleted log(s)." }
        if ($s.RefreshError) { $result += " Unable to refresh the log list: $($s.RefreshError)" }
        if ($s.LoadError) { $result += " Unable to read the selected log: $($s.LoadError)" }
        $s.Status.Text = $result
        if ($failures.Count -or $s.RefreshError -or $s.LoadError) { & $s.ReportDeleteError $s $result }
    }
    catch {
        $s.Status.Text = "Unable to delete logs: $($_.Exception.Message)"
        & $s.ReportDeleteError $s $s.Status.Text
    }
}
$list.Tag = $state
$list.Add_SelectedIndexChanged({ param($sender, $eventArgs) & $sender.Tag.Load $sender.Tag })
$apply.Tag = $state
$apply.Add_Click({ param($sender, $eventArgs) & $sender.Tag.Load $sender.Tag })
$refresh.Tag = $state
$refresh.Add_Click({ param($sender, $eventArgs) & $sender.Tag.Refresh $sender.Tag })
$delete.Tag = $state
$delete.Add_Click({ param($sender, $eventArgs) & $sender.Tag.Delete $sender.Tag $false })
$deleteAll.Tag = $state
$deleteAll.Add_Click({ param($sender, $eventArgs) & $sender.Tag.Delete $sender.Tag $true })
$copy.Tag = $state
$copy.Add_Click({
    param($sender, $eventArgs)
    $s = $sender.Tag
    $text = if ($s.Content.SelectionLength) { $s.Content.SelectedText } else { $s.Content.Text }
    if (-not $text) { $s.Status.Text = 'There is no log text to copy.'; return }
    try {
        [Windows.Forms.Clipboard]::SetText($text)
        $s.Status.Text = 'Copied log text to the clipboard.'
    }
    catch { $s.Status.Text = "Unable to copy log text: $($_.Exception.Message)" }
})
$auto.Tag = $state
$auto.Add_CheckedChanged({
    param($sender, $eventArgs)
    if ($sender.Checked) { $sender.Tag.Timer.Start() } else { $sender.Tag.Timer.Stop() }
})
$timer.Tag = $state
$timer.Add_Tick({ param($sender, $eventArgs) & $sender.Tag.Refresh $sender.Tag })
$form.Add_Disposed({ param($sender, $eventArgs) $sender.Tag.Timer.Dispose() })
$form.Controls.AddRange(@($logLabel, $list, $levelLabel, $level, $sinceLabel, $since,
    $untilLabel, $until, $searchLabel, $search, $apply, $auto, $content, $refresh, $delete, $deleteAll, $copy, $status))
$form.Tag = $state
$returnForm = $false
try {
    Add-PAWUiRibbon -Form $form -ScriptPath $PSCommandPath -CloseButton $close
    $form.Controls['PAWRibbon'].Controls['PAWRibbonTitle'].Text = 'PAW Logs'
    Set-PAWUiTheme -Control $form
    $list.ItemHeight = [Math]::Max(32, [Windows.Forms.TextRenderer]::MeasureText('Ag', $list.Font).Height + 12)
    & $state.Refresh $state
    if ($CreateOnly) { $returnForm = $true; return $form }
    $null = $form.ShowDialog()
}
finally { if (-not $returnForm) { $form.Dispose() } }
