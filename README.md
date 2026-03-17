# X.509 Certificate Viewer for IntelliJ IDEA

A premium, open-source plugin for inspecting X.509 certificates and keystores with a focus on readability and developer experience.

![Preview](https://raw.githubusercontent.com/JuanTorchia/certificate-viewer-open/main/resources/preview.png)

## Features

- **Multi-Format Support**: Works with `.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx`, `.jks`, and `.jceks`.
- **Premium UI v2.0**: Card-based layout with clean typography and hierarchical data display.
- **Validity Monitoring**: Visual timeline and progress bars showing certificate lifespan and expiration status.
- **Expert Metadata**: Automatic calculation of SHA-256 fingerprints, Subject/Issuer details, and Serial Numbers.
- **Developer Tools**: Single-click "Copy to Clipboard" for all sensitive metadata.
- **Security First**: Interactive and secure password prompting for encrypted keystores.
- **IDE Native**: Deep integration with the IntelliJ Editor system.

## Installation

1. Open **Settings/Preferences** (`Ctrl+Alt+S`).
2. Navigate to **Plugins**.
3. Search for "X.509 Certificate Viewer" (once published) or **Install from Disk** using the provided `.zip` artifact.
4. Restart the IDE to apply file associations.

## Usage

Simply double-click any certificate or keystore file in the **Project** view. The viewer will automatically open in a new editor tab. If the file is a password-protected keystore, a secure dialog will prompt for the password.

## Building from Source

```bash
git clone https://github.com/JuanTorchia/certificate-viewer-open.git
cd certificate-viewer-open
./gradlew build
```

The plugin ZIP will be generated in `build/distributions/`.

## License

This project is licensed under the **Apache License 2.0**.
