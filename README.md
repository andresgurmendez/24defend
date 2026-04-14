# 24Defend

Anti-phishing link protection for mobile devices.

## Structure

```
ios/          — iOS app (SwiftUI + NetworkExtension packet tunnel)
backend/      — Python FastAPI backend (DynamoDB + domain investigation agent)
```

## iOS

See [ios/DISTRIBUTION.md](ios/DISTRIBUTION.md) for Apple Developer setup and distribution.

```bash
cd ios
xcodegen generate
open TwentyFourDefend.xcodeproj
```

## Backend

```bash
cd backend
docker compose up --build
# API at http://localhost:8080
# Docs at http://localhost:8080/docs
```
