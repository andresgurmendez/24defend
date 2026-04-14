# 24Defend — Distribution & Apple Account Risks

## Apple Developer Account Requirements

### Account types

| Account | Cost | What works |
|---------|------|------------|
| Free Apple ID | $0 | Simulator UI only. No NetworkExtension — VPN toggle fails at runtime. Device deploys expire after 7 days. |
| Apple Developer Program (Personal) | $99/year | Full functionality. May need to request NetworkExtension entitlement separately (1–3 business days). TestFlight + App Store. |
| Apple Developer Enterprise | $299/year | Same as above + in-house distribution. Overkill for MVP. |

### NetworkExtension entitlement

The `packet-tunnel-provider` entitlement may not be available by default. If Xcode fails to create a provisioning profile:

1. Request it at https://developer.apple.com/contact/request/network-extension/
2. Use case description: "DNS-based phishing link protection for consumer mobile app"
3. Approval typically takes 1–3 business days

### Signing identity vs. device iCloud account

The Apple Developer account used to sign the app is **independent** of the iCloud account on the target iPhone. Any iPhone can install a dev-signed app regardless of its iCloud login — the user just needs to trust the developer certificate once (Settings → General → VPN & Device Management).

---

## Distribution Options

### TestFlight (recommended for demos and sales)

- Upload build via App Store Connect → invite testers by email
- Testers install TestFlight app, accept invite, install 24Defend
- No Xcode needed on their end
- Builds expire after **90 days** — push a new build to renew
- Internal testers (same App Store Connect team, up to 100): **no Apple review**
- External testers (up to 10,000): **light review required** (usually <24h, but NetworkExtension apps may take longer on first submission)

### Ad Hoc

- Register each device's UDID in the developer portal
- Build `.ipa` with Ad Hoc provisioning profile
- Distribute via Finder, Apple Configurator, or MDM
- **Limit: 100 device UDIDs per membership year** (UDIDs persist even if removed)
- No Apple review

### Direct from Xcode

- Connect device via USB, build and run
- Fine for one-off demos on your own machine
- Recipient must trust the developer certificate on their device

### App Store

- Full Apple review process
- Expect 1–2 rejections for NetworkExtension apps before approval
- Include a detailed reviewer note explaining the local DNS filtering approach

---

## Apple Account Ban Risks

### Real risks relevant to 24Defend

**1. Misrepresenting VPN functionality (MEDIUM risk)**
Apple is strict about apps that install VPN profiles. Requirements:
- Clearly explain to the user why a VPN configuration is needed
- The VPN must do exactly what the description says (DNS filtering, not data collection)
- Do not use the VPN to harvest traffic, inject ads, or track browsing
- Privacy policy must explicitly describe what the VPN does and does not do

**2. NetworkExtension entitlement abuse (LOW risk)**
Apple granted the entitlement for a stated purpose. The app must match what was described in the entitlement request. Do not add functionality beyond "DNS-based phishing link protection" without updating the entitlement justification.

**3. TestFlight as App Store bypass (MEDIUM risk if abused)**
TestFlight is for testing, not permanent production distribution. Running indefinitely on TestFlight to avoid App Store review can result in account action. Use TestFlight for the MVP/testing phase, then submit to the App Store for production.

**4. Private API usage (LOW risk)**
Apple scans binaries for private API calls. This project uses only public APIs (`NetworkExtension`, `NWConnection`, `NEPacketTunnelProvider`). If a dependency introduces private API usage, Apple will reject the binary — repeated submissions after warnings can escalate.

### Things that do NOT cause bans

- App submission rejections (normal, especially for NetworkExtension apps)
- Bugs or crashes in the app
- Low-quality early versions
- Slow responses to App Review feedback (though faster is better)

### What escalates to account-level action

- Repeated submissions that ignore previous rejection feedback
- Fraud: fake reviews, ranking manipulation, creating new accounts after a ban
- Malware or data harvesting (especially through VPN profiles)
- Submitting many near-identical apps (spam)

---

## Pre-Submission Checklist

### Before TestFlight / App Store submission

- [ ] **Privacy policy** hosted at a public URL, stating:
  - DNS queries are checked locally against a blocklist
  - No browsing data is collected or transmitted to external servers
  - The VPN configuration is used solely for DNS-level phishing protection
  - No user traffic is routed through external servers
- [ ] **App description** clearly states: "local DNS filtering to block phishing links — no traffic leaves the device"
- [ ] **Reviewer note** (in App Store Connect) explaining:
  - How the VPN works (local DNS interception, not a traditional VPN)
  - That it only intercepts DNS queries on port 53
  - That allowed queries are forwarded to a public DNS resolver (e.g., 1.1.1.1)
  - Offer a demo video or screen recording if possible
- [ ] **No debug/test code** that logs full URLs, captures traffic, or does anything beyond DNS filtering
- [ ] **VPN permission prompt** in the app includes clear user-facing explanation of why the VPN configuration is needed
- [ ] **Bundle ID** is the one you want long-term (transferring apps between accounts is possible but painful)

### On rejection (expected for first submission)

1. Do not panic — this is normal for NetworkExtension apps
2. Read the rejection reason in the Resolution Center carefully
3. Reply with a detailed explanation of the use case
4. Resubmit with any requested changes
5. Escalate via the App Review Board if the rejection seems incorrect

---

## Long-Term Considerations

- **Account ownership**: if 24Defend becomes a company product, create an Organization developer account and transfer the app. Plan the bundle ID accordingly (e.g., `com.24defend.app` rather than `com.personalname.24defend`)
- **Entitlement continuity**: the NetworkExtension entitlement is tied to the developer account. A new account requires a new entitlement request
- **TestFlight → App Store transition**: plan to submit to the App Store before relying on 24Defend for real users. TestFlight's 90-day expiry and Apple's expectation that it's temporary make it unsuitable for long-term distribution
