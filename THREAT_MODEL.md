# Threat model

## Assets

Developer machine, repository contents, credentials, network authority, container runtime state, and human approval decisions.

## Adversaries

- malicious or compromised repository metadata
- a prompt-injected coding agent proposing a deceptively simple command
- a dependency or lifecycle hook whose effects are not visible in the approval string

## Defenses

- EffectLock does not execute the proposed command
- no LLM or remote API is used
- parsers are bounded to local project metadata
- evidence is structured and source-attributed
- unknown dependency behavior is explicitly reported
- policy can deny named effect classes before execution occurs elsewhere

## Residual risks

Static prediction is incomplete. Scripts can dynamically construct commands, dependencies can contain their own hooks/build scripts, Git configuration can change after prediction, and TOCTOU exists between prediction and later execution by another system. EffectLock must therefore be used as evidence for an approval decision, not as a sandbox or proof of safety.
