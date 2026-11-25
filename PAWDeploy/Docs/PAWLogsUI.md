# View PAWDeploy logs

**Logs** is available next to Help and Close in the Community and Enterprise menus. The viewer
reads `.log` files from the current user's `%TEMP%\PAWDeploy` folder.
This is the TEMP folder of the account running the toolkit.
For another account or a saved collection, start the viewer with:

```powershell
.\Tools\PAWLogsUI.ps1 -LogFolder 'D:\PAW-Staging\Logs'
```

Select a log, filter by level, inclusive local dates and literal search text,
then select **Apply filters**. **Refresh** reloads the file list and selected
log. Enable **Auto refresh (5 s)** to reload while a process is writing.
The viewer shows at most the latest 1,000 matching entries. Continuation lines,
including stack traces, remain with their timestamped entry.

**Delete log** removes the selected log; **Delete all logs** removes the `.log`
files in the current log folder, including hidden logs. Both ask for confirmation,
and deletion cannot be undone. Other files and subfolders are not deleted. A
running process may recreate a log or prevent its deletion; failures are reported
in the viewer.

Select text and choose **Copy selection** or press Ctrl+C. If no text is
selected, **Copy selection** copies the entire displayed result. Logs may
contain sensitive information; review them before sharing.

The CLI returns PowerShell objects and does not limit results unless `-Tail` is
specified:

```powershell
.\Tools\Get-PAWLogs.ps1
.\Tools\Get-PAWLogs.ps1 -Name 'New-PAWVM.log' -Level ERROR -Tail 50
.\Tools\Get-PAWLogs.ps1 -Name 'New-PAWVM.log' -Since (Get-Date).AddDays(-1) -Text 'Defender'
.\Tools\Get-PAWLogs.ps1 -Name 'PAWMenu.log' -LogFolder 'D:\PAW-Staging\Logs'
```

`-Since` and `-Until` are inclusive local timestamps. Searches are literal
and case-insensitive, including continuation lines. Text before the first valid
timestamped entry is returned as `UNSTRUCTURED`; timestamp filters exclude it.
`INFO`/`Information` and `WARN`/`Warning` are equivalent. The `RawText` property
contains the original entry text, while `Message` excludes its first header.
Read errors are reported; the reader does not create, truncate or delete logs.
