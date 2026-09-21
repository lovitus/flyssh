from pathlib import Path
import subprocess

p = Path('pkg/wingui/wingui_windows.go')
s = p.read_text()
a = s.index('type sortMode string'); b = s.index('const (\n\tbuttonHeight', a); s = s[:a] + s[b:]
a = s.index('type fileEntry struct'); b = s.index('type navState struct', a); s = s[:a] + s[b:]
a = s.index('func (a *app) localSortChanged()'); b = s.index('func (a *app) startTransfer(', a); s = s[:a] + s[b:]
a = s.index('func sortEntries('); b = s.index('func validateLocalDir(', a); s = s[:a] + s[b:]
s = s.replace('\tremoteSort   *walk.ComboBox\n', '\tremoteSort   *walk.ComboBox\n\tlocalSortDirection *walk.PushButton\n\tremoteSortDirection *walk.PushButton\n')
s = s.replace('\tremoteSortMode    sortMode\n', '\tremoteSortMode    sortMode\n\tlocalSortDescending bool\n\tremoteSortDescending bool\n')
for side in ('local', 'remote'):
    line = next(l for l in s.splitlines() if 'ComboBox{AssignTo: &a.' + side + 'Sort,' in l)
    new = line.replace('MaxSize: Size{Width: 92}', 'ToolTipText: "Sort by name, file size or modification date", MinSize: Size{Width: 78}, MaxSize: Size{Width: 78}')
    new += '\n\t\t\t\t\t\tPushButton{AssignTo: &a.' + side + 'SortDirection, Text: "Asc", ToolTipText: sortDirectionToolTip(sortByName, false), MinSize: Size{Width: 52, Height: buttonHeight}, MaxSize: Size{Width: 52}, OnClicked: func() { a.reversePaneSort(side' + side.capitalize() + ') }},'
    s = s.replace(line, new)
a = s.index('\ta.mu.Lock()\n\tsortEntries(items, a.localSortMode)', s.index('func (a *app) refreshLocal()')); b = s.index('\n}', a)
s = s[:a] + '\ta.replacePaneItems(sideLocal, dir, items)' + s[b:]
a = s.index('\ta.mu.Lock()\n\tsortEntries(entries, a.remoteSortMode)', s.index('func (a *app) loadRemoteUnderOperation')); b = s.index('\n\treturn nil', a)
s = s[:a] + '\ta.replacePaneItems(sideRemote, dir, entries)' + s[b:]
p.write_text(s)
subprocess.run(['gofmt', '-w', str(p)], check=True)
assert subprocess.check_output(['git', 'hash-object', str(p)], text=True).strip() == '6b93bc687a955766e3f5a195bb8bf7d0f6a3f340'

for name in ('windows-gui.yml', 'request-release.yml'):
    p = Path('.github/workflows') / name
    s = p.read_text()
    assert s.count("'^TestWindowsGUIHashes$'") == 1
    p.write_text(s.replace("'^TestWindowsGUIHashes$'", "'^TestWindowsGUI(Hashes|Sorting)$'"))

p = Path('CHANGELOG.md')
s = p.read_text(encoding='utf-8')
header = '# Changelog / 更新日志\n\n'
assert s.startswith(header)
notes = '''## v2.0.16 (2026-09-21)

### Features / 新功能

- **Name / Size / Date sorting** in both Windows file panes, with an **Asc / Desc** button. Names default to A-Z, sizes to largest first, and modification dates to newest first / 两侧文件列表支持名称、大小、修改日期排序及升降序切换。
- Preserve selected filenames when sorting, including when sorting the other pane. Sort key and direction survive refresh and navigation; folders stay first and unknown metadata stays last / 排序保留所选文件，刷新及切换目录保留排序方式；文件夹优先，未知信息排在末尾。
- Serialize listing updates with sort changes on the UI thread so a background refresh cannot restore a stale order / 列表更新与排序在 UI 线程统一处理，避免后台刷新覆盖新的排序方式。

### Verification / 验证

- Portable tests for all keys/directions, numeric metadata, unknown/zero/large values, deterministic ties and selection remapping.
- Native packaged-executable tests for both panes, selection/hash preservation, refresh and navigation, alongside the existing hash regression tests.
- The existing CI-gated release pipeline verifies downloaded Windows and Linux amd64 binaries.

---

'''
p.write_text(header + notes + s[len(header):], encoding='utf-8')
