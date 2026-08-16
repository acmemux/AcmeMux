# Native configuration editing

AcmeMux edits the adopted native lego YAML and supported credential files. Those files remain authoritative and can still be used directly with lego. AcmeMux does not keep a second desired configuration, expose raw YAML editing, or accept arbitrary environment variables or commands.

## Supported content

The current forms cover storage, supported ACME accounts and certificate authorities, certificate definitions, renewal controls, HTTP-01, and DNS-01 through Azure DNS, Cloudflare, DigitalOcean, DuckDNS, and Amazon Route 53.

Content outside that supported set is preserved. Recognized but unsupported content blocks AcmeMux-managed operations, and unknown structures can also block editing because AcmeMux cannot prove that rewriting them is safe.

The configuration screen can report:

- **Creation required:** no workspace is selected and a reviewed configuration target is available.
- **Ready:** the current native files are valid and supported.
- **Unsupported:** native content is preserved but falls outside the current supported set.
- **Invalid:** the current configuration or referenced file does not meet the managed contract.
- **Recovery required:** a prior multi-file change was interrupted and must be resolved first.

## Preview and save

Always preview before saving. Preview does not write a file. It shows the logical fields and public before-and-after values that will change. Secret fields show only whether a value is present, replaced, removed, or unchanged.

Saving repeats the runtime, workspace, source-file, and path checks. If another process changes the YAML, credential file, ownership, permissions, or referenced paths after preview, AcmeMux rejects the save and requires a fresh review.

Supported YAML changes preserve unedited native content, ordering, scalar style, and comments where possible, but exact whitespace is not guaranteed after a change. Credential-file updates preserve unrelated lines and comments.

## Secrets and credential files

Existing secrets are write-only. The browser never receives the stored value, and a preview never compares a submitted value with the stored value. Use **Keep**, **Replace**, or **Remove** as offered by the form.

Only credential keys belonging to the selected supported provider can be changed. Extra valid keys remain in the file but block managed operations until you decide how to handle them outside AcmeMux. Malformed files, duplicate keys, variable expansion, unsafe ownership, links, or insufficient permissions also block editing.

New and replaced native files are private to the AcmeMux service account. Direct lego use should run as that same intended account.

## Create the first configuration

When no workspace exists, choose an existing safe working directory and either the conventional `.lego.yml` name or an explicit absent configuration path. Storage and HTTP webroot directories must already exist. AcmeMux can create a referenced provider credential file only when its parent and target pass the displayed safety review.

Creation never overwrites an existing target and does not adopt the workspace until the newly active files pass a fresh review.

## Interrupted change recovery

A change involving YAML and a credential file updates one file at a time. A service or filesystem failure between files can leave recovery required. While recovery is pending, AcmeMux blocks further edits and certificate operations.

The screen classifies the current state and offers only actions safe for that state:

| State | Operator action |
| --- | --- |
| **Unapplied** | Discard the recognized staged files and keep the original workspace. |
| **Applied** | Revalidate and finalize the active files. |
| **Partial** | Stop other writers, repair the active YAML and credential files on the host, then adopt the reviewed current files. |
| **Ambiguous** | Inspect and repair the active files and only the staging entries identified by the incident, then adopt the reviewed current files. |

An interrupted first creation that activated any file also requires **Adopt current** after a complete fresh review.

Do not use wildcard deletion for `.acmemux-edit-*` files, and do not manually promote a staging file into place. Treat every staging file as confidential. A substituted or unrelated file is deliberately left untouched and keeps recovery blocked.

All recovery actions repeat administrator authorization and current path checks. If evidence changed again, reload and review it before continuing.

## Troubleshooting

- **Changed evidence:** Reload and review the current native files instead of overwriting them.
- **Unsupported content:** Use the displayed native location to decide whether to keep managing that content outside AcmeMux or replace it with supported fields.
- **Invalid configuration:** Correct every displayed issue in one preview; AcmeMux will not save a candidate that remains invalid.
- **Unsafe path:** Correct host ownership, mode, links, or access outside AcmeMux, then inspect again.
- **Recovery required:** Resolve the displayed interrupted change before re-adopting a runtime or workspace or starting a certificate operation.

See [CA and HTTP-01 configuration](ca-certificate-http.md), [DNS providers](dns-providers.md), and [workspace adoption](workspace-adoption.md) for supported fields and host prerequisites.
