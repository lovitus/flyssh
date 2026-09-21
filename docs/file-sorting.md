# Sorting in the Windows transfer GUI

The Local and Remote panes each have a **Sort** dropdown with **Name**, **Size**
and **Date**, plus an **Asc / Desc** button that reverses the current order.

| Sort key | Default order | Reverse order |
| --- | --- | --- |
| Name | A to Z (case-insensitive) | Z to A |
| Size | Largest first | Smallest first |
| Date | Newest modification date first | Oldest first |

Folders stay above files in either direction. Sizes use actual byte counts and
dates use modification timestamps, not the formatted text in the list. Unknown
metadata sorts last within its folder/file group. Equal sizes or dates use a
deterministic alphabetical tie-break.

Each pane keeps its own sort key and direction during refreshes and navigation.
Changing the sort preserves the same selected files/folders by name, even when
their list indexes move. Sorting the other pane does not clear your selection.
The Hash, MV, Del and transfer actions therefore still target the selected names.
A directory reload clears selections, as before; sort choices last for the GUI
session, not across application restarts.

Portable tests cover every key/direction, large and unknown values, ties and
selection remapping. Native Windows tests drive the packaged executable and the
published release against temporary local files and a loopback SSH server,
checking both panes, selection/hash preservation, refresh and navigation. The
existing hash tests remain enabled.
