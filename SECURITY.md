# Security

Please report vulnerabilities privately to the repository owner before public disclosure.

EffectLock intentionally does not execute inspected commands. A security issue includes any path by which command analysis itself executes attacker-controlled project code, accesses secrets beyond the named project metadata, makes an unexpected network request, escapes the selected project when reading policy/metadata, or writes receipts outside the selected project.

## v0.2 policy safety

Policy files are never auto-loaded. An explicit policy path must remain under the selected project directory. On supported POSIX systems EffectLock opens policy path components with `O_NOFOLLOW`, bounds policy size to 64 KiB, and rejects hardlinked policy files.

EffectLock remains a static analyzer, not a sandbox. Use OS-level containment when executing untrusted commands.
