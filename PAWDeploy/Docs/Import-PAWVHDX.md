# Import VHDX files

See [Commandline Samples](CommandlineSamples.md) for a complete PowerShell example that imports a VHDX and uses it to deploy a PAW.

Use the menu's **Import VHDX** tool to select one or more `.vhdx` files. Every
file is copied into the folder configured as
`Settings.Configuration.VHDFolder` in `Config.json`. As with Run Script and
WDAC imports, a replacement prompt follows the file selection: **Yes** allows
replacement, **No** refuses the import if a filename already exists, and
**Cancel** aborts. The completed import displays the destination paths.
While copying, an animated progress window shows that the import is running;
it does not estimate a percentage or remaining time. Leave it open until the
success or error message appears.

The command-line tool supports the same operation:

```powershell
.\Tools\Import-PAWVHDX.ps1 -Path 'D:\Downloads\Reference.vhdx'
.\Tools\Import-PAWVHDX.ps1 -Path 'D:\Images\First.vhdx','D:\Images\Second.vhdx' -Replace
```

The console shows the filename and file number while each image is copied,
without estimating copy progress.

Use `-ConfigPath` to select another Config.json. `-Replace` permits overwriting
same-name files; `-WhatIf` previews the file copies and folder creation without
writing files. Import results and failures are logged to
`%TEMP%\PAWDeploy\Import-PAWVHDX.log`. Files are staged in the destination
folder before publication, so replacement requires enough free space for the
new image alongside the existing one. If a later file fails, earlier imports
remain in place and the error identifies them.

The shared PowerShell module also exposes the importer directly:

```powershell
Import-Module .\Functions\PAWUtility\PAWUtility.psd1
Import-PAWVHDX -Path 'D:\Downloads\Reference.vhdx' -ConfigPath 'C:\PAWDeploy\Config\Config.json'
```

The module command also accepts legacy `.vhd` images, including those exported
by `Export-PAWVHDXImage`. The graphical picker selects `.vhdx` files.
