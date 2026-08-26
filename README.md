# Onitrack

Onitrack is an experimental command-line client for accessing accepted Apple
Find My People location shares from a non-Apple host. It authenticates an Apple
Account, registers APNs and IDS identities, discovers accepted relationships,
manages local aliases and relationship keys, and retrieves and decrypts
SearchParty location reports.

The software uses reverse-engineered private Apple protocols. It is intended
only for accounts and location shares that the operator is authorized to
access. It is not an official Apple client and is not suitable as the sole
source of safety-critical location data.

## Repository status

The package version is `0.1.0`. The current implementation provides:

- interactive Apple Account authentication, including supported two-factor
  authentication methods;
- optional authentication with a real Mac device profile;
- encrypted local secret storage using `age`;
- APNs activation and courier-token management;
- IDS delegate authentication, handle lookup, certificate issuance, and
  multiplex service registration;
- discovery of accepted Find My People relationships through FMF;
- anonymized relationship identifiers and local aliases;
- strict import and validation of P-224 People location keys;
- SearchParty report retrieval and local location decryption;
- a short-lived APNs/IDS receiver for automatic People key acquisition;
- redacted protocol diagnostics intended not to expose handles, identifiers,
  keys, or coordinates.

Apple Account authentication, APNs connectivity, IDS registration, FMF
relationship discovery, and IDS directory queries have been exercised against
Apple's production services.

Automatic relationship-key acquisition is not currently successful end to end.
Apple accepts the FMF and SearchParty `distributeKeys` request sequence, and both
the local receiver identity and the selected participant's NGM identities
verify successfully, but no IDS application message with command `242` has
been delivered in live tests. The command therefore reports the key as pending
after its timeout. The receive, cryptographic verification, acknowledgement,
and persistence paths are implemented and covered by synthetic tests, but have
not processed a live key-delivery packet.

Location retrieval requires a valid relationship key. The repository supports
supplying that key through the validated stdin import command.

The repository does not contain a background polling service, HTTP health
endpoint, route evaluator, Prometheus exporter, or NixOS service module.

## Command interface

The packaged executable is `onitrack`. The top-level command groups are:

```text
onitrack version
onitrack doctor
onitrack auth ...
onitrack apple ...
onitrack people ...
```

The implemented operational commands are:

```text
onitrack auth provision
onitrack auth status
onitrack auth upgrade

onitrack apple register

onitrack people list
onitrack people alias set
onitrack people alias setup
onitrack people key import
onitrack people key acquire
onitrack people location get
```

Use `--help` at any level for the current arguments. For example:

```sh
nix run .#onitrack -- people key acquire --help
```

### Output modes

Commands that can expose People information require an explicit output mode.

- `--anonomyse` returns salted identifiers and derived status information. The
  misspelling is retained as part of the current CLI interface.
- `--plain` returns raw relationship or location information and should be used
  only in a controlled private environment.
- `--debug-redacted` writes protocol diagnostics to stderr with sensitive fields
  removed or replaced by salted HMAC values.

`people key import` and `people key acquire` accept only anonymized output mode.
Private key material for import is read from stdin rather than a command-line
argument.

## Configuration and secret storage

The default configuration directory is relative to the current working
directory:

```text
.config/onitrack
```

It can be changed with `--config-dir` or the `ONITRACK_CONFIG_DIR` environment
variable.

Onitrack creates the directory with mode `0700` and state files with mode
`0600`. Sensitive state is stored in `secrets.age`, encrypted to a local age
identity. Encrypted sections include Apple Account session state, APNs
certificate and private key material, IDS registration state, anonymization
salt, advertised IDs, and People location keys. Non-secret JSON files contain
metadata and local alias configuration.

The local age identity grants access to all encrypted Onitrack state. It must be
protected and backed up according to the operator's security requirements.

Mac validation JSON contains device information and short-lived validation
material. It must not be committed, logged, or retained longer than necessary
for authentication and registration.

## Apple registration

`apple register` activates APNs and registers the IDS multiplex service. A
mac-registration-provider JSON document can be supplied with
`--validation-json PATH` or through stdin with `--validation-json -`.

The repository includes a macOS helper for generating this document:

```sh
scripts/generate-mac-validation-json.sh /private/path/validation.json
```

The helper downloads the pinned mac-registration-provider release, writes the
output with mode `0600`, and checks the required JSON fields. The resulting
validation data is short-lived.

`--replace-device-registration` performs a fresh APNs/IDS registration using
Onitrack's logical-device UUID while retaining the supplied Mac profile. It
requires fresh validation JSON and replaces encrypted registration state only
after IDS registration succeeds.

## People relationships and keys

Accepted relationships can be listed without printing raw handles or FMF IDs:

```sh
nix run .#onitrack -- people list --anonomyse
```

The returned `person_id` is a salted HMAC used for local alias configuration:

```sh
nix run .#onitrack -- people alias set Team PERSON_ID
```

The interactive equivalent is:

```sh
nix run .#onitrack -- people alias setup
```

A relationship key can be imported from Base64 on stdin. The parser requires
an 85-byte P-224 public-point/private-scalar blob and verifies that the scalar
derives the supplied public point before encrypted persistence.

```sh
printf '%s' "$KEY_B64" | nix run .#onitrack -- people key import \
  --person-id PERSON_ID \
  --advertised-id ADVERTISED_ID \
  --anonomyse
```

Avoid placing real key material in shell history or scripts. The variable above
is illustrative; direct private stdin is preferable.

The automatic receiver can be invoked explicitly:

```sh
nix run .#onitrack -- people key acquire \
  --alias Team \
  --anonomyse \
  --wait-seconds 120 \
  --debug-redacted
```

A timeout currently produces an anonymized `pending` result. It does not modify
or remove an existing valid key.

## Location retrieval

With a configured alias and validated key, Onitrack submits a SearchParty fetch,
selects the expected advertised ID, decrypts the newest valid report, and
normalizes coordinates, horizontal accuracy, and source timestamp.

An anonymized request omits raw coordinates and returns availability, age,
accuracy, and salted position/report digests:

```sh
nix run .#onitrack -- people location get \
  --alias Team \
  --anonomyse \
  --debug-redacted
```

Raw coordinates are available only with the explicit `--plain` mode:

```sh
nix run .#onitrack -- people location get --alias Team --plain
```

## Build and tests

The repository is packaged as a Nix flake. The declared systems are
`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`.
Production-protocol testing to date has been performed from `x86_64-linux`.

Build the application and run its packaged pytest suite with:

```sh
nix build .#onitrack
```

Run all flake checks, including Ruff, with:

```sh
nix flake check
```

Open the development environment with:

```sh
nix develop
```

The current suite uses synthetic fixtures and does not contain captured live
APNs packets, Apple identifiers, People handles, location keys, or coordinates.
It covers account-state handling, encrypted persistence, APNs/IDS registration,
FMF request construction, IDS pair-EC verification, malformed and unrelated key
deliveries, P-224 validation, SearchParty decryption, CLI output requirements,
redaction, acknowledgement timing, and timeout behavior.

## Dependencies and protocol references

The Nix package pins and patches the dependencies used for Apple protocol
access, including:

- [FindMy.py](https://github.com/malmeloo/FindMy.py) for Apple Account and
  SearchParty authentication support;
- [pypush](https://github.com/JJTech0130/pypush) for APNs, IDS-related primitives,
  and emulated validation support;
- `age` for local encrypted state;
- Python `cryptography` for certificate and message cryptography.

The People protocol implementation is based principally on
[Reverse-engineering Find My People on Linux](https://zerotistic.blog/posts/find-my-people-linux/).
[RustPush](https://github.com/OpenBubbles/rustpush) is used as a supporting
reference for APNs, IDS, FMF, SearchParty, and NGM behavior.

## License

Onitrack is licensed under the MIT License. See [LICENSE](LICENSE).
