# APK Sentinel — Real‑Time APK Security Analyzer

A Flask web app that analyzes Android APKs for suspicious permissions, malicious code patterns, and risk levels — with live, streaming progress via Server‑Sent Events (SSE).

- Real-time analysis stream
- Risk scoring and threat levels
- Hashes (MD5, SHA1, SHA256)
- Fallback analysis without `aapt`
- Clean, modern UI

## Demo

Upload an APK, watch live logs, and auto-redirect to the results when the job completes.

## Features

- Live progress streaming during analysis (SSE)
- Hash calculation: MD5, SHA1, SHA256
- Permission analysis with suspicious and high-risk flags
- Malicious string pattern scanning inside APK contents
- Threat level and recommendations
- VirusTotal check placeholder (ready for future API integration)
- Auto-cleanup of uploaded files

## Project Structure

- `app.py` — Flask app and analyzer
- `templates/index.html` — Upload page
- `templates/results.html` — Results + live log
- `static/style.css` — Styling
- `requirements.txt` — Dependencies

## Quick Start

1) Install dependencies

- Ensure Python 3.10+ (3.11 recommended)
- Install packages:
  ```
  pip install -r requirements.txt
  ```

2) Run the app

```
python app.py
```

Open http://localhost:5001 in your browser.

3) Analyze an APK

- Upload any `.apk` to see risk analysis, warnings, and recommendations

## Real-Time Streaming

This app streams progress to the browser during analysis using Server‑Sent Events. You’ll see a live log, then the page automatically redirects to the final results when the job completes.

## Test APK (included)

A synthetic APK for quick validation:

- Path: `sample-malicious.apk` (project root)
- Contains high-risk permissions and malicious strings to trigger alerts

Upload it on the home page to verify the live flow and risk detection.

## Optional: Rich Metadata via aapt

If you want detailed metadata:

1. Install Android SDK Build Tools and add `aapt` to PATH
2. Verify with:
   ```
   aapt version
   ```
3. The app will automatically try `aapt` and fall back if unavailable

## Configuration

No environment variables are required by default.

Planned options:

- VirusTotal API key (e.g., `VT_API_KEY`) for real checks

## Security and Privacy

- Uploaded files are removed after analysis
- This tool provides preliminary analysis; do not rely solely on it for security decisions
- Always download apps from official sources and use comprehensive endpoint protection

## Troubleshooting

- `aapt` not found
  - The app falls back to reading APK contents without `aapt`. To enable richer metadata, install build-tools and add `aapt` to PATH.

- 500 error after upload
  - Ensure you’re on the latest code and refresh. Template guards render correctly during live streaming.

- Large APKs
  - The default max upload size is 50MB. Adjust `app.config['MAX_CONTENT_LENGTH']` in `app.py` if needed.

## Roadmap

- Real VirusTotal integration with API key
- Deep static analysis (DEX/Smali) via androguard
- Batch analysis, reporting, and exports
- Persistent history and user sessions
- Rule engine for advanced behavioral heuristics

## Contributing

- Issues and PRs are welcome
- Keep changes minimal and consistent with current style
- Discuss larger features in an issue first to align on scope
