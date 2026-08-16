# Supported lego executables

AcmeMux uses one lego executable that you install and maintain. It does not download, discover, replace, or upgrade lego for you. Selecting an executable only reviews its identity; it does not contact an ACME server or issue a certificate.

## Current support

Current support is limited to Linux amd64 and these exact reviewed artifacts:

| Source identity | Accepted lego identity | Executable SHA-256 |
| --- | --- | --- |
| Official lego v5.3.1 Linux amd64 release | `5.3.1` or `v5.3.1` | `36c97b1ed369c2c46d7a4dde0d635d8e742b080c27c36d58933a8029f7811624` |
| Reviewed local build of tag v5.3.1 with Go 1.26.6 | `5.3.1` or `v5.3.1` | `e55089f626ffe1725de10b71bac366a6f6ee8d88cddc7fbff8fdb1cd3ad4897f` |
| Reviewed source revision `2a58c3522708e4c7393a67be691bd0c3a16d8441` | the same 40-character revision | `ef3819a069a79e8b79306665cac076b9ce53e31f63c60b953d62740f8f4b59b4` |

The reviewed source-revision build was observed with unsafe group-writable permissions. Identical bytes can be accepted only after you place them at a safe non-writable path.

Another binary built from the same tag or commit is not automatically supported. Its digest and build evidence differ. Other operating systems and CPU architectures are not currently supported.

## Prepare the executable

Use an absolute path. Every path component must be free of symbolic links, and the final file must be:

- a nonempty regular file no larger than 512 MiB;
- owned by root or the account running AcmeMux;
- not writable by group or others;
- free of setuid, setgid, and sticky mode bits;
- executable by the AcmeMux account; and
- free of Linux file capabilities, except the exact reviewed `cap_net_bind_service=ep` capability when lego must bind a low port.

Modes such as `0755`, `0750`, or `0700` are common depending on ownership. Prefer a root-owned executable that the service account can execute but cannot modify. Do not share the AcmeMux account with unrelated processes.

## Inspect and adopt

In the Runtime section:

1. Enter the absolute executable path.
2. Inspect the candidate.
3. Compare its canonical path, SHA-256 digest, version, platform, ownership, permissions, capability, and build identity with the source you intended to install.
4. Acknowledge the review and adopt it only when AcmeMux reports it supported.

AcmeMux stores the reviewed identity, not the executable bytes. Before later workspace reads or certificate operations, it checks the selected file again. A changed path, file, digest, owner, mode, capability, version, build identity, or support policy blocks use until you inspect and adopt a supported replacement.

## Supported features

A supported lego executable does not make every compiled lego feature available through AcmeMux. The current application supports the certificate authorities, HTTP-01 modes, and five DNS providers listed in the public configuration guides. Other providers and native fields remain unsupported even when the binary contains them.

## Troubleshooting

- **Missing:** Restore the intended file at the reviewed path or inspect a new absolute path.
- **Unsafe:** Correct symbolic links, file type, ownership, write permissions, special mode bits, execute access, capability, platform, or unknown digest. Do not weaken the service account to bypass the review.
- **Malformed output:** The executable's bounded version response or embedded build identity did not match a supported artifact.
- **Timed out:** The executable or underlying filesystem did not complete inspection in time.
- **Unverified or incompatible:** The file is known but does not resolve to a currently supported exact artifact and feature manifest.
- **Changed:** The adopted evidence no longer matches. Inspect and adopt a supported replacement before continuing.

If inspection is temporarily busy, wait and try again. AcmeMux permits only one executable inspection at a time.
