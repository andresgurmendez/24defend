# /ios-build — Regenerate, build, test the iOS app from CLI

Encapsulates the xcodegen → restore-Info.plist → xcodebuild dance. Use this
instead of doing it by hand — the Info.plist restore step is the most
commonly forgotten step in the codebase.

## When to use

- After adding or removing Swift files (xcodegen has to regenerate the project)
- Before opening a PR that touches iOS — verify it still builds and tests pass
- To build for the simulator from CLI (CI-friendly, no Xcode GUI needed)

## Prerequisites

- macOS with Xcode 15+ installed
- `xcodegen` installed: `brew install xcodegen`
- iOS Simulator runtime for iPhone 15 (Xcode usually installs this)

## Usage

```
/ios-build                 # regenerate, build for simulator
/ios-build test            # regenerate, build, run unit tests
/ios-build open            # regenerate, restore plists, open in Xcode
/ios-build clean           # delete derived data, regenerate, build
```

## Commands — regenerate and restore Info.plist

```bash
cd /Users/mgurmendez/git/24defend-mono/ios

# 1. Regenerate the xcodeproj from project.yml
xcodegen generate

# 2. Restore the bits xcodegen overwrites
#    See CLAUDE.md "iOS project regeneration" — this is THE footgun.
#
#    App Info.plist (TwentyFourDefend/Info.plist):
#      - CFBundleDisplayName = "24Defend"
#
#    Tunnel Info.plist (TwentyFourDefendPacketTunnel/Info.plist):
#      - NSExtension dict with NEPacketTunnelProvider configuration
#
#    Use `git diff` to verify nothing critical disappeared:
git diff TwentyFourDefend/Info.plist TwentyFourDefendPacketTunnel/Info.plist
#    If diffs look bad: `git checkout` the plists to restore, then re-apply
#    any intentional edits.
```

## Commands — build from CLI

```bash
cd /Users/mgurmendez/git/24defend-mono/ios

# Simulator build (no signing required)
xcodebuild build \
  -project TwentyFourDefend.xcodeproj \
  -scheme TwentyFourDefend \
  -destination 'platform=iOS Simulator,name=iPhone 15' \
  -configuration Debug

# Strict version: clean derived data first
rm -rf ~/Library/Developer/Xcode/DerivedData/TwentyFourDefend-*
```

For a device build (real iPhone), see `ios/DISTRIBUTION.md` — code signing
and provisioning live there, not here.

## Commands — run tests from CLI

```bash
cd /Users/mgurmendez/git/24defend-mono/ios

xcodebuild test \
  -project TwentyFourDefend.xcodeproj \
  -scheme TwentyFourDefend \
  -destination 'platform=iOS Simulator,name=iPhone 15' \
  -configuration Debug
```

The cross-validation tests assert Swift bloom filter / feature extractor
agreement with the Python ground truth. If they fail, either:
- The Python implementation changed and the JSON fixture is stale
  (regenerate by running `cd ../ml && .venv/bin/python train.py`), or
- The Swift implementation drifted from Python. Fix the Swift side.

## Commands — open in Xcode

```bash
cd /Users/mgurmendez/git/24defend-mono/ios
xcodegen generate
# (restore Info.plists — see above)
open TwentyFourDefend.xcodeproj
```

In Xcode: select the `TwentyFourDefend` scheme, target an iPhone 15 simulator,
Cmd+R to build & run. NetworkExtension does not function in the simulator —
only the UI runs.

## What lives where

```
ios/
├── project.yml                              # xcodegen input (declares targets, signing)
├── TwentyFourDefend/                        # Main app (SwiftUI)
│   ├── Info.plist                           # ← xcodegen overwrites
│   └── TwentyFourDefend.entitlements
├── TwentyFourDefendPacketTunnel/            # NEPacketTunnelProvider extension
│   ├── Info.plist                           # ← xcodegen overwrites (NSExtension)
│   └── TwentyFourDefendPacketTunnel.entitlements
├── Shared/                                  # Used by both targets — keep pure (no UIKit)
│   ├── DomainChecker.swift                  # Infrastructure allowlist lives here
│   ├── BrandRuleEngine.swift                # User-facing warning logic
│   ├── BloomFilter.swift                    # Python-style signed mod (see CLAUDE.md)
│   └── PhishingClassifier.swift             # On-device ML model loader
├── Tests/                                   # Swift unit tests
├── mmh3_ground_truth.json                   # Cross-validation fixture (must agree with Python)
└── python_feature_ground_truth.json         # Cross-validation fixture
```

## Gotchas

### Info.plist diff after `xcodegen generate`
Documented but worth repeating. The fix is:
1. `git diff TwentyFourDefend/Info.plist` — see what xcodegen ripped out
2. `git checkout TwentyFourDefend/Info.plist` to restore
3. Same for `TwentyFourDefendPacketTunnel/Info.plist`
4. If you needed to *change* the plists, edit `project.yml` instead of the
   plists — xcodegen will preserve your `project.yml`-driven changes.

### Code signing failure on simulator build
You shouldn't need signing for simulator. If you see "no provisioning profile",
clean derived data and re-run. If you set a team in Xcode UI, xcodegen may
have written it into project.yml — verify and remove.

### Cross-validation tests fail
The Swift and Python implementations of mmh3 and the feature extractor must
agree byte-for-byte. If a test fails:
1. Run `cd ../ml && .venv/bin/python -c "from features import extract_features; print(extract_features('test.com'))"` for the failing domain.
2. Compare with the Swift output (Tests log it).
3. If Python changed: regenerate the ground-truth JSON. If Swift drifted: fix Swift.

### NetworkExtension doesn't load in simulator
Expected. The packet tunnel is only loadable on a real device with the
`packet-tunnel-provider` entitlement provisioned. See `DISTRIBUTION.md`.

### `xcodebuild` says "no such destination"
Run `xcodebuild -showsdks` and `xcrun simctl list devices` to see what's
actually installed. Adjust the `-destination` flag. Use `name=iPhone 15`
generically — Xcode picks the right runtime.

### Swarm of warnings about deployment target
Set in `project.yml` (`iOS: "16.0"`). If you bump this, also bump any
`@available` annotations and re-verify NetworkExtension API availability.

## Next step

If the simulator build is green, your Swift change is structurally fine. The
next test is on a real device — and that's a separate ceremony documented in
`ios/DISTRIBUTION.md`.
