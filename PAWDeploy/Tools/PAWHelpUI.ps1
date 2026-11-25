<#
.SYNOPSIS
    Reads local toolkit documentation in a graphical window.
.DESCRIPTION
    Lists Markdown guides and formats headings, emphasis, lists, tables,
    and code without executing content or accessing the internet.
    Opens the requested guide initially.
.PARAMETER Document
    Guide filename in PAWDeploy\Docs, for example PAWDeployUI.md.
.PARAMETER WindowX
    Left screen coordinate when supplied together with WindowY.
.PARAMETER WindowY
    Top screen coordinate when supplied together with WindowX.
.EXAMPLE
    .\Tools\PAWHelpUI.ps1 -Document PAWMenu.md
.NOTES
    Created: 2026-11-06
    Updated: 2026-11-11
    Version: 2.0.0.6

    Author - Mikael Nystrom
    Twitter: @mikael_nystrom
    Blog   : http://www.deploymentbunny.com

    Additional original notes and attribution:
    Original Author: PSHydrationKit maintainers

    Disclaimer:
    This script is provided "AS IS" with no warranties, confers no rights and
    is not supported by the author.
.LINK
    http://www.deploymentbunny.com
.LINK
    https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms
#>

[CmdletBinding()]
param([string]$Document = 'PAWMenu.md', [int]$WindowX, [int]$WindowY)

# Edition branding (logo); Build rewrites this value for the Community package.
$script:PAWEdition = 'Community'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PAWHelpDocumentPath {
    param(
        [Parameter(Mandatory=$true)][string]$DocsPath,
        [Parameter(Mandatory=$true)][string]$Document
    )
    if ([IO.Path]::GetFileName($Document) -cne $Document -or
        [IO.Path]::GetExtension($Document) -ine '.md') {
        throw 'Select a Markdown filename in the Docs folder.'
    }
    $path = Join-Path $DocsPath $Document
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Guide not found: $path" }
    (Resolve-Path -LiteralPath $path).Path
}

function Set-PAWHelpMarkdown {
    param(
        [Parameter(Mandatory=$true)]$TextBox,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Content
    )
    $fonts = @{
        Body = [System.Drawing.Font]::new('Segoe UI', 11)
        Bold = [System.Drawing.Font]::new('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
        Italic = [System.Drawing.Font]::new('Segoe UI', 11, [System.Drawing.FontStyle]::Italic)
        Code = [System.Drawing.Font]::new('Consolas', 10)
        H1 = [System.Drawing.Font]::new('Segoe UI', 22, [System.Drawing.FontStyle]::Bold)
        H2 = [System.Drawing.Font]::new('Segoe UI', 17, [System.Drawing.FontStyle]::Bold)
        H3 = [System.Drawing.Font]::new('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
    }
    $palette = Get-PAWUiPalette
    $TextBox.BackColor = $palette.ReadOnly
    $TextBox.ForeColor = $palette.Text
    $TextBox.Clear()
    $TextBox.SuspendLayout()
    try {
        $lines = @($Content -split '\r?\n')
        $inCode = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $TextBox.SelectionStart = $TextBox.TextLength
            $TextBox.SelectionFont = $fonts.Body
            $TextBox.SelectionColor = $palette.Text
            $TextBox.SelectionBackColor = $palette.ReadOnly
            $TextBox.SelectionIndent = 16
            if ($line -match '^\s*```') { $inCode = -not $inCode; continue }
            if ($inCode) {
                $TextBox.SelectionFont = $fonts.Code
                $TextBox.SelectionBackColor = $palette.Field
                $TextBox.SelectionIndent = 28
                $TextBox.AppendText($line + "`n")
                continue
            }
            if ($line -match '^\s*\|') {
                $rows = New-Object 'System.Collections.Generic.List[object]'
                while ($i -lt $lines.Count -and $lines[$i] -match '^\s*\|') {
                    $cells = @($lines[$i].Trim().Trim('|').Split('|') | ForEach-Object {
                        $_.Trim().Replace('**', '').Replace('`', '') -replace '\[([^\]]+)\]\([^)]+\)', '$1'
                    })
                    if ($lines[$i] -notmatch '^\s*\|(?:\s*:?-+:?\s*\|)+\s*$') { $rows.Add($cells) }
                    $i++
                }
                $i--
                $widths = @{}
                foreach ($cells in $rows) {
                    for ($column = 0; $column -lt $cells.Count; $column++) {
                        if (-not $widths.ContainsKey($column)) { $widths[$column] = 0 }
                        $widths[$column] = [Math]::Max($widths[$column], $cells[$column].Length)
                    }
                }
                $TextBox.SelectionFont = $fonts.Code
                foreach ($cells in $rows) {
                    $padded = for ($column = 0; $column -lt $cells.Count; $column++) {
                        $cells[$column].PadRight($widths[$column])
                    }
                    $TextBox.AppendText(($padded -join '  |  ') + "`n")
                }
                $TextBox.AppendText("`n")
                continue
            }
            if ($line -match '^(#{1,6})\s+(.+)$') {
                $level = [Math]::Min($Matches[1].Length, 3)
                $TextBox.SelectionFont = $fonts["H$level"]
                $TextBox.SelectionColor = $palette.Heading
                $TextBox.AppendText($Matches[2] + "`n`n")
                continue
            }
            if ($line -match '^\s*[-*]\s+(.+)$') { $line = '-  ' + $Matches[1]; $TextBox.SelectionIndent = 28 }
            elseif ($line -match '^\s*\d+\.\s+') { $TextBox.SelectionIndent = 28 }
            elseif ($line -match '^>\s?(.*)$') {
                $line = $Matches[1]
                $TextBox.SelectionIndent = 28
                $TextBox.SelectionColor = $palette.MutedText
            }
            $line = $line -replace '\[([^\]]+)\]\([^)]+\)', '$1'
            $position = 0
            foreach ($span in [regex]::Matches($line, '\*\*(.+?)\*\*|`([^`]+)`|(?<!\*)\*([^*]+)\*(?!\*)')) {
                $TextBox.SelectionFont = $fonts.Body
                $TextBox.AppendText($line.Substring($position, $span.Index - $position))
                if ($span.Groups[1].Success) { $TextBox.SelectionFont = $fonts.Bold; $value = $span.Groups[1].Value }
                elseif ($span.Groups[2].Success) { $TextBox.SelectionFont = $fonts.Code; $value = $span.Groups[2].Value }
                else { $TextBox.SelectionFont = $fonts.Italic; $value = $span.Groups[3].Value }
                $TextBox.AppendText($value)
                $position = $span.Index + $span.Length
            }
            $TextBox.SelectionFont = $fonts.Body
            $TextBox.AppendText($line.Substring($position) + "`n")
        }
        $TextBox.SelectionStart = 0
        $TextBox.SelectionLength = 0
        $TextBox.ScrollToCaret()
    } finally {
        $TextBox.ResumeLayout()
        foreach ($item in $fonts.Values) { $item.Dispose() }
    }
}

$docsPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Docs'))
$initialPath = Get-PAWHelpDocumentPath -DocsPath $docsPath -Document $Document
$guides = @(Get-ChildItem -LiteralPath $docsPath -Filter '*.md' -File | Sort-Object Name)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = [System.Windows.Forms.Form]::new()
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
$script:LogPath = Join-Path (Resolve-PAWLogFolder) 'PAWHelpUI.log'
Write-PAWLog -Message 'PAW Help starting.' -LogPath $script:LogPath
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$form.Text = $script:PAWToolTitle
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1344, 756)
$form.MinimumSize = New-Object System.Drawing.Size(1344, 756)
$form.MaximumSize = New-Object System.Drawing.Size(1344, 756)
$form.MaximizeBox = $false
$PawUiUtilityManifest = Join-Path $root 'Functions\PAWUIUtility\PAWUIUtility.psd1'
Import-Module $PawUiUtilityManifest -Force -ErrorAction Stop
$palette = Get-PAWUiPalette
$form.BackColor = $palette.Background
$windowIcon = Get-PAWWindowIcon
$form.Icon = $windowIcon
$close = New-Object System.Windows.Forms.Button
$close.Text = 'Close'
$close.Add_Click({ $form.Close() })
$split = [System.Windows.Forms.SplitContainer]::new()
$split.Dock = 'Fill'
$split.Size = [System.Drawing.Size]::new(1100, 650)
$split.SplitterDistance = 270
$list = [System.Windows.Forms.ListBox]::new()
$list.Dock = 'Fill'
$list.DisplayMember = 'Name'
$list.IntegralHeight = $false
foreach ($guide in $guides) { [void]$list.Items.Add($guide) }
$text = [System.Windows.Forms.RichTextBox]::new()
$text.Dock = 'Fill'
$text.ReadOnly = $true
$text.DetectUrls = $false
$text.WordWrap = $true
$text.BackColor = $palette.ReadOnly
$font = [System.Drawing.Font]::new('Segoe UI', 11)
$text.Font = $font
$pathLabel = [System.Windows.Forms.Label]::new()
$pathLabel.Dock = 'Top'
$pathLabel.Height = 32
$pathLabel.TextAlign = 'MiddleLeft'
$pathLabel.AutoEllipsis = $true
$split.Panel1.Controls.Add($list)
$split.Panel2.Controls.Add($text)
$split.Panel2.Controls.Add($pathLabel)
$form.Controls.Add($split)
$list.Add_SelectedIndexChanged({
    if ($null -eq $list.SelectedItem) { return }
    try {
        $selectedPath = Get-PAWHelpDocumentPath -DocsPath $docsPath -Document $list.SelectedItem.Name
        $content = Get-Content -LiteralPath $selectedPath -Raw -Encoding UTF8 -ErrorAction Stop
        Set-PAWHelpMarkdown -TextBox $text -Content $content
        $pathLabel.Text = $selectedPath
        Write-PAWLog -Message "Opened guide: $selectedPath." -LogPath $script:LogPath

    } catch {
        Write-PAWLog -Level ERROR -Message "Help failed: $($_.Exception.Message)" -LogPath $script:LogPath
        $text.Clear()
        $pathLabel.Text = 'Unable to read guide'
        [void][System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Help error', 'OK', 'Error')
    }
})
Add-PAWUiRibbon -Form $form -ScriptPath $PSCommandPath -CloseButton $close -HelpAction {
    for ($index = 0; $index -lt $list.Items.Count; $index++) {
        if ($list.Items[$index].Name -eq 'PAWHelpUI.md') { $list.SelectedIndex = $index; break }
    }
}
for ($i = 0; $i -lt $list.Items.Count; $i++) {
    if ($list.Items[$i].FullName -eq $initialPath) { $list.SelectedIndex = $i; break }
}
$split.BringToFront()
if ($PSBoundParameters.ContainsKey('WindowX') -and $PSBoundParameters.ContainsKey('WindowY')) {
    $form.StartPosition = 'Manual'
    $form.Location = New-Object System.Drawing.Point($WindowX, $WindowY)
}
$form.Add_Shown({ Set-PAWWindowForeground -Form $form })
try { [void]$form.ShowDialog() }
finally {
    $form.Dispose()
    $font.Dispose()
    $windowIcon.Dispose()
}
