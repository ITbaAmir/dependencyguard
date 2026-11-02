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

## Understanding the results

The Windows interface uses plain-language status labels and colours:

| Result | Meaning | Recommended action |
| --- | --- | --- |
| Red: Action needed | OSV reports a known security issue for this exact version. | Open the security notice, update the dependency, then scan again. |
| Yellow: Review | The version is not fixed or a dependency file could not be read. | Pin an exact version or correct the file. |
| Green: No known issue | OSV has no known issue for this exact version. | Keep the dependency updated and scan regularly. |
| Blue: Not checked online | The scan did not use OSV, or OSV was unavailable. | Run the online check again when possible. |

Select any result to see a fuller explanation. The **Open security notice** button
opens the public OSV entry. References such as `GHSA-...` are identifiers for a
GitHub Security Advisory; they are shown only in the detailed explanation.

The selected-result area is a selectable, copyable report. It includes the exact
source file, package, version, explanation, recommended next step, and any
security reference. Use **Copy full result** to share it with a teammate or paste
it into a support request.

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
