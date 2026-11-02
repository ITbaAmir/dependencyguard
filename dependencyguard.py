"""DependencyGuard scans dependency files for security risks.

PSEUDOCODE:
1. Find dependency files in the selected project folder.
2. Read dependencies for Python, JavaScript/TypeScript, Java, and Go.
3. Flag dependencies without an exact version.
4. Optionally check exact versions against the OSV vulnerability database.
5. Display results in the terminal, a JSON report, or the Windows GUI.
"""

from __future__ import annotations

import argparse
import json
import re
import threading
import tomllib
import urllib.error
import urllib.request
import xml.etree.ElementTree as element_tree
from dataclasses import asdict, dataclass
from pathlib import Path


APP_NAME = "DependencyGuard"
OSV_URL = "https://api.osv.dev/v1/querybatch"
SKIPPED_FOLDERS = {".git", ".venv", "venv", "node_modules", "build", "dist", "target"}
SUPPORTED_FILES = {
    "requirements.txt": "Python", "pyproject.toml": "Python", "Pipfile": "Python",
    "package.json": "JavaScript/TypeScript", "pom.xml": "Java",
    "build.gradle": "Java", "build.gradle.kts": "Java", "go.mod": "Go",
}
ECOSYSTEMS = {"Python": "PyPI", "JavaScript/TypeScript": "npm", "Java": "Maven", "Go": "Go"}


@dataclass
class Dependency:
    """One dependency found in a supported project file."""

    language: str
    name: str
    version: str | None
    source_file: str

    @property
    def ecosystem(self) -> str:
        return ECOSYSTEMS[self.language]


@dataclass
class Finding:
    """One result produced by the dependency scan."""

    severity: str
    dependency: Dependency
    message: str
    advisory: str = ""


def exact_version(specification: str) -> str | None:
    """Return an exact version, never guess a version from a range."""
    value = specification.strip().strip('"\'')
    match = re.fullmatch(r"(?:==|===|v)?([0-9][A-Za-z0-9.+_-]*)", value)
    return match.group(1) if match else None


def find_dependency_files(project_folder: Path) -> list[Path]:
    """Find known dependency files and skip generated dependency folders."""
    files = []
    for file_path in project_folder.rglob("*"):
        if any(part in SKIPPED_FOLDERS for part in file_path.parts):
            continue
        if file_path.is_file() and file_path.name in SUPPORTED_FILES:
            files.append(file_path)
    return sorted(files)


def parse_requirements(file_path: Path) -> list[Dependency]:
    """Read regular package lines from requirements.txt."""
    dependencies = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", ".")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", line)
        if match:
            name, specification = match.groups()
            dependencies.append(Dependency("Python", name, exact_version(specification), str(file_path)))
    return dependencies


def parse_python_toml(file_path: Path) -> list[Dependency]:
    """Read standard project dependencies and common Poetry or Pipfile declarations."""
    document = tomllib.loads(file_path.read_text(encoding="utf-8"))
    result = []
    declarations = document.get("project", {}).get("dependencies", [])
    for declaration in declarations:
        match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", declaration)
        if match:
            name, specification = match.groups()
            result.append(Dependency("Python", name, exact_version(specification), str(file_path)))
    groups = [document.get("tool", {}).get("poetry", {}).get("dependencies", {}), document.get("packages", {}), document.get("dev-packages", {})]
    for group in groups:
        for name, specification in group.items():
            if name.lower() == "python":
                continue
            version = specification if isinstance(specification, str) else specification.get("version", "")
            result.append(Dependency("Python", name, exact_version(version), str(file_path)))
    return result


def parse_package_json(file_path: Path) -> list[Dependency]:
    """Read npm dependencies, including development and optional packages."""
    document = json.loads(file_path.read_text(encoding="utf-8"))
    result = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, specification in document.get(section, {}).items():
            result.append(Dependency("JavaScript/TypeScript", name, exact_version(str(specification)), str(file_path)))
    return result


def parse_pom(file_path: Path) -> list[Dependency]:
    """Read Maven dependencies that use literal package coordinates."""
    result = []
    root = element_tree.parse(file_path).getroot()
    for node in root.findall(".//{*}dependency"):
        group = node.findtext("{*}groupId", "").strip()
        artifact = node.findtext("{*}artifactId", "").strip()
        version = node.findtext("{*}version", "").strip()
        if group and artifact:
            result.append(Dependency("Java", f"{group}:{artifact}", exact_version(version), str(file_path)))
    return result


def parse_gradle(file_path: Path) -> list[Dependency]:
    """Read standard Gradle string dependency coordinates."""
    result = []
    pattern = re.compile(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[('\\\"]+([^:'\\\"]+):([^:'\\\"]+):([^'\\\")]+)")
    for group, artifact, version in pattern.findall(file_path.read_text(encoding="utf-8")):
        result.append(Dependency("Java", f"{group}:{artifact}", exact_version(version), str(file_path)))
    return result


def parse_go_mod(file_path: Path) -> list[Dependency]:
    """Read direct and grouped Go module requirements."""
    result = []
    in_block = False
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.split("//", 1)[0].strip()
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        content = line.removeprefix("require ").strip()
        if in_block or line.startswith("require "):
            match = re.match(r"([^\s()]+)\s+(v[^\s]+)", content)
            if match:
                name, version = match.groups()
                result.append(Dependency("Go", name, exact_version(version), str(file_path)))
    return result


def parse_file(file_path: Path) -> list[Dependency]:
    """Use the correct parser for one dependency file."""
    parsers = {
        "requirements.txt": parse_requirements, "pyproject.toml": parse_python_toml, "Pipfile": parse_python_toml,
        "package.json": parse_package_json, "pom.xml": parse_pom, "build.gradle": parse_gradle,
        "build.gradle.kts": parse_gradle, "go.mod": parse_go_mod,
    }
    return parsers[file_path.name](file_path)


def local_findings(dependencies: list[Dependency]) -> list[Finding]:
    """Warn when a dependency cannot be reliably matched to one release."""
    return [Finding("medium", dependency, "No exact version was found. Pin this dependency before trusting vulnerability results.") for dependency in dependencies if not dependency.version]


def osv_findings(dependencies: list[Dependency]) -> list[Finding]:
    """Ask OSV about known vulnerabilities for exact package versions."""
    checked = [item for item in dependencies if item.version]
    if not checked:
        return []
    payload = {"queries": [{"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.version} for item in checked]}
    request = urllib.request.Request(OSV_URL, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "DependencyGuard/1.0"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            results = json.load(response).get("results", [])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        return [Finding("info", item, f"OSV lookup failed: {error}") for item in checked]
    findings = []
    for dependency, result in zip(checked, results):
        for vulnerability in result.get("vulns", []):
            message = vulnerability.get("summary") or vulnerability.get("details", "Known vulnerability")
            findings.append(Finding("known", dependency, message.replace("\n", " "), vulnerability.get("id", "OSV advisory")))
    return findings


def scan_project(project_folder: Path, check_online: bool) -> tuple[list[Dependency], list[Finding]]:
    """Scan every supported file and optionally query the OSV database."""
    dependencies, findings = [], []
    for file_path in find_dependency_files(project_folder):
        try:
            dependencies.extend(parse_file(file_path))
        except (OSError, UnicodeDecodeError, ValueError, element_tree.ParseError, tomllib.TOMLDecodeError) as error:
            placeholder = Dependency(SUPPORTED_FILES[file_path.name], file_path.name, None, str(file_path))
            findings.append(Finding("info", placeholder, f"Could not read this file: {error}"))
    findings.extend(local_findings(dependencies))
    if check_online:
        findings.extend(osv_findings(dependencies))
    return dependencies, findings


def print_report(dependencies: list[Dependency], findings: list[Finding]) -> None:
    """Show a readable terminal report."""
    print(f"{APP_NAME}: {len(dependencies)} dependencies found")
    for item in dependencies:
        print(f"- {item.ecosystem}: {item.name} {item.version or '(unversioned)'}")
    print(f"\nFindings: {len(findings)}")
    for finding in findings:
        advisory = f" [{finding.advisory}]" if finding.advisory else ""
        print(f"- {finding.severity.upper()}: {finding.dependency.name}: {finding.message}{advisory}")


def write_report(report_file: Path, dependencies: list[Dependency], findings: list[Finding]) -> None:
    """Write a JSON report that can be stored with scan results."""
    data = {"dependencies": [asdict(item) for item in dependencies], "findings": [asdict(item) for item in findings]}
    report_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Report written to {report_file}")


class DependencyGuardApp:
    """A small graphical interface for Windows users."""

    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import filedialog, ttk

        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.minsize(920, 500)
        self.filedialog, self.folder = filedialog, tk.StringVar(value=str(Path.cwd()))
        self.status = tk.StringVar(value="Choose a project folder and start a scan.")
        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Project folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.folder, width=82).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="Browse", command=self.choose_folder).grid(row=0, column=2)
        ttk.Button(frame, text="Scan locally", command=lambda: self.start_scan(False)).grid(row=1, column=1, sticky="w", pady=10)
        ttk.Button(frame, text="Check OSV vulnerabilities", command=lambda: self.start_scan(True)).grid(row=1, column=1, sticky="e", pady=10)
        columns = ("severity", "ecosystem", "package", "version", "advisory", "message")
        self.results = ttk.Treeview(frame, columns=columns, show="headings")
        for column, heading, width in (("severity", "Severity", 75), ("ecosystem", "Ecosystem", 95), ("package", "Package", 180), ("version", "Version", 100), ("advisory", "Advisory", 100), ("message", "Message", 410)):
            self.results.heading(column, text=heading)
            self.results.column(column, width=width, anchor="w")
        self.results.grid(row=2, column=0, columnspan=3, sticky="nsew")
        ttk.Label(frame, textvariable=self.status).grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)

    def choose_folder(self) -> None:
        """Open the folder selection dialog."""
        selected = self.filedialog.askdirectory(initialdir=self.folder.get())
        if selected:
            self.folder.set(selected)

    def start_scan(self, check_online: bool) -> None:
        """Start scan work without freezing the user interface."""
        folder = Path(self.folder.get())
        if not folder.is_dir():
            self.status.set("Choose an existing project folder.")
            return
        self.status.set("Checking OSV vulnerabilities..." if check_online else "Scanning project...")
        threading.Thread(target=self.run_scan, args=(folder, check_online), daemon=True).start()

    def run_scan(self, folder: Path, check_online: bool) -> None:
        """Perform scan work in a background thread."""
        dependencies, findings = scan_project(folder, check_online)
        self.root.after(0, self.show_results, dependencies, findings)

    def show_results(self, dependencies: list[Dependency], findings: list[Finding]) -> None:
        """Display dependency rows and their findings."""
        self.results.delete(*self.results.get_children())
        for item in dependencies:
            self.results.insert("", "end", values=("info", item.ecosystem, item.name, item.version or "unversioned", "", "Dependency found"))
        for finding in findings:
            item = finding.dependency
            self.results.insert("", "end", values=(finding.severity, item.ecosystem, item.name, item.version or "unversioned", finding.advisory, finding.message))
        self.status.set(f"Scan complete: {len(dependencies)} dependencies and {len(findings)} findings.")

    def run(self) -> None:
        """Open the graphical interface."""
        self.root.mainloop()


def main() -> None:
    """Run the terminal scan or the Windows GUI."""
    parser = argparse.ArgumentParser(description="Scan dependency files for known security issues.")
    parser.add_argument("--folder", type=Path, default=Path.cwd(), help="Project folder to scan.")
    parser.add_argument("--offline", action="store_true", help="Skip the OSV vulnerability lookup.")
    parser.add_argument("--gui", action="store_true", help="Open the Windows graphical interface.")
    parser.add_argument("--output", type=Path, help="Write results as JSON.")
    arguments = parser.parse_args()
    if arguments.gui:
        DependencyGuardApp().run()
        return
    if not arguments.folder.is_dir():
        parser.error(f"Folder does not exist: {arguments.folder}")
    dependencies, findings = scan_project(arguments.folder, not arguments.offline)
    print_report(dependencies, findings)
    if arguments.output:
        write_report(arguments.output, dependencies, findings)


if __name__ == "__main__":
    main()
