# GitHub private backup (development)

Open **GitHub private backup** in the companion and confirm device ownership.
Sign in using the displayed GitHub device code. The browser is always opened at
`https://github.com/login/device`; return to the companion after approving.
Closing the screen cancels requests. Returning from the browser resumes polling
within the original code lifetime and the 15-minute owner session.

The OAuth app requests `repo`. GitHub defines this as broad repository access;
the UI discloses that permission before sign-in. The adapter accepts only the
authenticated user's own private, writable repository. Select an existing state
repository when available; creation is an explicit separate action. Source
collaborators receive no personal-vault access from this flow.

Inspect an existing branch before uploading. The selected head is the commit
parent, and the upload creates one new immutable backup directory under
`frankenstein/backups/<archive-sha256>/`. Its five files match `vault/backup.py`:
`vault.age`, `backup.json`, and three files under `recovery/`. The base tree
preserves unrelated repository files. The adapter verifies uploaded blob IDs,
downloads all five files for byte comparison, rechecks repository privacy and
the branch head, then updates the ref with `force=false`. Competing sibling
commits are rejected; the user must inspect again. This is not an exclusive
server lock against an administrator force-moving the branch. Interrupted
uploads may leave unreachable encrypted Git objects; no partial backup commit
is deliberately published.

Cloud backups are limited to **8 MiB total**. Credential amendment is limited
to **16 MiB portable bundles**. Larger vaults use the existing USB/PC adapters;
this implementation does not promise unlimited cloud archives. API calls use
fixed GitHub HTTPS hosts, no redirects, bounded input/output and timeouts.
There is no embedded client secret, automatic scope expansion or token logging.

Tokens are inside `credentials/github.json` in the encrypted portable vault.
Amendment preserves the local identity, kit ID, context and existing independent
recovery capsule and re-encrypts to both local and emergency recipients. A
Keystore-backed encrypted journal records refresh intent and the returned pair
before repacking. Ambiguous refresh failure requires a new login instead of
replaying a possibly invalidated refresh token. Successful repacking uses the
existing compare-and-swap generation activation. A journal conflict does not
overwrite a different active generation. Old encrypted objects remain until a
future explicit retention/garbage-collection policy; removing a journal pointer
does not claim secure erasure of those objects or backups.

Credentials carry the originating device certificate fingerprint. A replica
must authorize independently before this adapter will use or refresh those
tokens. This avoids concurrent use of one rotating token; it does not implement
a distributed multi-device credential registry. GitHub tokens recovered from an
old backup may already be revoked or expired, so recovery must allow re-login.

To recover independently, inspect the desired repository/branch, enter the
externally recorded archive SHA-256, and download a recovery ZIP. The adapter
checks the exact Git file allowlist, blob IDs, archive digest and capsule hashes.
This is ciphertext integrity verification, not proof of emergency decryption.
On an independent PC use `frankenstein recover-backup --help` from the installed
engine, or `python3 vault/recovery_backup.py --help` from a source checkout. Supply
the ZIP file's SHA-256 and the external recovery passphrase. Successful recovery
authenticates the age archive and restores the state. The Android download does
not replace the current phone vault. Keep the encrypted backup outside the
origin phone and keep the passphrase separately.

## Verification

`tests/native-portable.py` exercises amendment, identity preservation, rejected
input and independent recovery. Android JVM tests cover polling intervals,
slow-down, cancellation, scope/host validation, refresh and non-expiring tokens,
private ownership checks, publication races and corrupt read-back. Physical
instrumentation tests encrypted token storage, rotated-pair persistence,
crash-journal replay, ambiguous-refresh refusal and replica refusal using only
isolated synthetic credentials. They do not authorize a real account.

For owner-driven OAuth testing without touching an installed development vault,
build with `-PisolatedProof=true`. This installs `org.frankenstein.companion.dev.proof`
labelled **Frankenstein (isolated test)**. Create a fresh vault in its UI using
dummy machine/profile values and a private owner-chosen recovery passphrase.
Never authorize real GitHub tokens in a fixture whose recovery phrase is public.
Owner PIN, GitHub authorization and recovery passphrase entry remain manual.

Protocol references: [GitHub device flow and refresh](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps),
[Git trees](https://docs.github.com/en/rest/git/trees#create-a-tree),
[non-force reference updates](https://docs.github.com/en/rest/git/refs#update-a-reference).
