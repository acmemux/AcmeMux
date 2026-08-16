# Native workspace adoption

AcmeMux operates one native lego workspace. It can adopt an existing supported workspace or create the first supported configuration through the browser. Native configuration, credential files, ACME accounts, certificates, private keys, and archives remain on the host under lego's normal layout.

## Before adoption

- Adopt a [supported lego executable](runtime-compatibility.md).
- Run AcmeMux and lego under the same dedicated non-root account.
- Make the intended working directory and native files accessible to that account.
- Stop unrelated processes that might change the workspace during review.

AcmeMux reports unsafe or insufficient access. It never changes ownership, permissions, or path placement for you.

## Select a workspace

Every workspace has an absolute effective working directory. Choose one configuration mode:

- **Conventional:** AcmeMux checks `.lego.yml` first and `.lego.yaml` second in the working directory, matching lego's precedence.
- **Explicit:** Enter one absolute configuration path and the separate effective working directory.

Relative `storage`, DNS `envFile`, and HTTP `webroot` values resolve from the effective working directory, not from the configuration file's parent. Review every resolved path carefully before adoption. If no storage path is set, lego uses `.lego` below the working directory.

When both conventional names exist, `.lego.yml` wins and the other file is reported as shadowed. Correct unexpected duplicates before continuing.

## Path and permission requirements

The review covers:

- the working directory;
- the native YAML file and its parent directory;
- the storage directory;
- every referenced DNS credential file; and
- every HTTP webroot.

Managed paths cannot use symbolic links. Configuration and credential files must be regular, private, and not hard linked. Ownership, mode, and access must protect secrets while giving the service account the access required for reading, replacement, certificate storage, or challenge files.

For a new workspace, the working, storage, and webroot directories must already exist and be safe. AcmeMux creates only the reviewed configuration and supported credential files; it does not create or repair directories.

The adoption screen shows canonical paths, ownership, permissions, file identity, and access. AcmeMux checks them again before saving and during later operations. If a relevant file or path changes, managed actions stop until you review the current evidence.

Mounted filesystems must remain responsive and support ordinary Linux file identity and same-directory replacement. Avoid network or special filesystems whose link, rename, or synchronization behavior does not match those expectations.

## Certificate inventory

After adoption, AcmeMux uses the reviewed lego executable to read certificate inventory from the exact storage directory. This inventory action does not issue or renew certificates, contact a provider, or modify the workspace.

The browser receives certificate names, DNS names, issuer, expiration, native certificate path, and safe file metadata. It never receives certificate contents, private keys, ACME account data, or native resource documents.

A new empty storage directory can correctly produce an empty inventory. Other inventory failures block a current result and report the host or native evidence that needs attention.

## Changes after adoption

External lego use remains possible, but it can invalidate the reviewed evidence. After changing YAML, credentials, paths, ownership, permissions, or the executable outside AcmeMux, return to the browser and review the new state before starting a managed operation.

Do not edit the workspace externally while AcmeMux is saving configuration or running a certificate operation. External processes do not participate in AcmeMux's workspace lock.

If a configuration save was interrupted, resolve it through the configuration screen before trying to adopt another workspace. See [configuration recovery](native-configuration.md#interrupted-change-recovery).

## Troubleshooting states

- **Unadopted:** Select a supported executable and inspect a workspace.
- **Changed:** Reload and acknowledge current path and file evidence.
- **Missing or read-only:** Restore the intended path or correct service-account access outside AcmeMux.
- **Unsafe:** Remove links or unsafe types and correct ownership and mode.
- **Incompatible:** Preserve the native files and replace unsupported configuration with supported choices only when that is your intent.
- **Inventory unavailable:** Restore access to the reviewed executable and storage, then refresh.

See [native configuration editing](native-configuration.md) for supported forms and [security](security.md) for the trusted-host boundary.
