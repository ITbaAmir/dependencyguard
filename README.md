# DependencyGuard

DependencyGuard scans dependency files in Python, JavaScript/TypeScript, Java,
and Go projects. It flags dependencies without exact versions and can check exact
versions against the public [OSV vulnerability database](https://osv.dev/).

## Requirements

- Python 3.11 or newer
- Internet access only for the OSV vulnerability check
- No third-party Python packages are required

## Start the Windows GUI

```powershell
python dependencyguard.py --gui
```

Choose a project folder, then use **Scan locally** or **Check OSV vulnerabilities**.
The online check sends only package names, ecosystems, and exact versions to OSV.

## Use from the terminal

```powershell
python dependencyguard.py --folder "C:\\Projects\\myproject"
python dependencyguard.py --folder "C:\\Projects\\myproject" --offline
python dependencyguard.py --folder "C:\\Projects\\myproject" --output report.json
```

## Supported files

| Language | Files |
| --- | --- |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile` |
| JavaScript/TypeScript | `package.json` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Go | `go.mod` |

## Important limits

- An unpinned dependency is marked for review because it cannot be checked against one exact release.
- This tool reports known OSV advisories. It cannot guarantee that a dependency is safe or trustworthy.
- Dynamic Gradle versions and Maven property references are marked for review rather than guessed.
