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
import webbrowser
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
    """A plain-language graphical interface for Windows users."""

    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title("DependencyGuard – Dependency Security Check")
        self.root.minsize(900, 600)
        self.filedialog, self.messagebox = filedialog, messagebox
        self.folder = tk.StringVar(value=str(Path.cwd()))
        self.status = tk.StringVar(value="Choose a project folder and start a security check.")
        self.summary = tk.StringVar(value="No scan has been run yet.")
        self.selected_details = "Select a result to see a clear explanation and next step."
        self.row_details: dict[str, tuple[str, str]] = {}
        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Project folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.folder, width=82).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(frame, text="Choose folder", command=self.choose_folder).grid(row=0, column=2)
        ttk.Button(frame, text="Scan locally", command=lambda: self.start_scan(False)).grid(row=1, column=1, sticky="w", pady=10)
        ttk.Button(frame, text="Check security issues online", command=lambda: self.start_scan(True)).grid(row=1, column=1, sticky="e", pady=10)
        ttk.Button(frame, text="Help", command=self.show_help).grid(row=1, column=2, padx=(8, 0))
        ttk.Label(frame, textvariable=self.summary, font=("Segoe UI", 10, "bold")).grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 8))
        content = ttk.Panedwindow(frame, orient="vertical")
        content.grid(row=3, column=0, columnspan=3, sticky="nsew")
        table_area = ttk.Frame(content)
        table_area.columnconfigure(0, weight=1)
        table_area.rowconfigure(0, weight=1)
        columns = ("status", "package", "version", "meaning", "action")
        self.results = ttk.Treeview(table_area, columns=columns, show="headings", height=14)
        for column, heading, width in (
            ("status", "Status", 145), ("package", "Dependency", 180), ("version", "Version", 110),
            ("meaning", "What does this mean?", 300), ("action", "Recommended next step", 370),
        ):
            self.results.heading(column, text=heading)
            self.results.column(column, width=width, minwidth=80, anchor="w", stretch=True)
        self.results.tag_configure("danger", background="#FDE7E9", foreground="#9C0006")
        self.results.tag_configure("review", background="#FFF2CC", foreground="#7F6000")
        self.results.tag_configure("safe", background="#E2F0D9", foreground="#375623")
        self.results.tag_configure("info", background="#DDEBF7", foreground="#1F4E78")
        vertical_scrollbar = ttk.Scrollbar(table_area, orient="vertical", command=self.results.yview)
        horizontal_scrollbar = ttk.Scrollbar(table_area, orient="horizontal", command=self.results.xview)
        self.results.configure(yscrollcommand=vertical_scrollbar.set, xscrollcommand=horizontal_scrollbar.set)
        self.results.grid(row=0, column=0, sticky="nsew")
        vertical_scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew")
        self.results.bind("<<TreeviewSelect>>", self.show_selected_details)
        self.results.bind("<Configure>", self.resize_columns, add="+")
        details = ttk.LabelFrame(content, text="Explanation for the selected result", padding=8)
        self.details_text = scrolledtext.ScrolledText(details, wrap="word", height=9, font=("Segoe UI", 10))
        self.details_text.pack(anchor="w", fill="both", expand=True)
        self.details_text.bind("<Control-c>", self.copy_selected_text)
        detail_buttons = ttk.Frame(details)
        detail_buttons.pack(anchor="e", pady=(6, 0))
        self.copy_button = ttk.Button(detail_buttons, text="Copy full result", command=self.copy_full_result)
        self.copy_button.pack(side="left", padx=(0, 8))
        self.notice_button = ttk.Button(detail_buttons, text="Open security notice", command=self.open_notice, state="disabled")
        self.notice_button.pack(side="left")
        self.set_details(self.selected_details)
        content.add(table_area, weight=4)
        content.add(details, weight=1)
        ttk.Label(frame, textvariable=self.status).grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)

    def choose_folder(self) -> None:
        """Open the folder selection dialog."""
        selected = self.filedialog.askdirectory(initialdir=self.folder.get())
        if selected:
            self.folder.set(selected)

    def resize_columns(self, event: object) -> None:
        """Use available table width for the two explanatory columns."""
        width = getattr(event, "width", 0)
        if width < 650:
            return
        fixed_width = 435
        flexible_width = max(width - fixed_width, 420)
        self.results.column("status", width=145)
        self.results.column("package", width=180)
        self.results.column("version", width=110)
        self.results.column("meaning", width=int(flexible_width * 0.42))
        self.results.column("action", width=int(flexible_width * 0.58))

    def start_scan(self, check_online: bool) -> None:
        """Start scan work without freezing the user interface."""
        folder = Path(self.folder.get())
        if not folder.is_dir():
            self.status.set("Please choose an existing project folder.")
            return
        self.status.set("Checking known security issues ..." if check_online else "Scanning project folder ...")
        threading.Thread(target=self.run_scan, args=(folder, check_online), daemon=True).start()

    def run_scan(self, folder: Path, check_online: bool) -> None:
        """Perform scan work in a background thread."""
        dependencies, findings = scan_project(folder, check_online)
        self.root.after(0, self.show_results, dependencies, findings, check_online)

    def add_result(self, status: str, dependency: Dependency, meaning: str, action: str, tag: str, details: str, notice_url: str = "") -> None:
        """Add one plain-language result row and its selectable details."""
        row_id = self.results.insert("", "end", values=(status, dependency.name, dependency.version or "Not fixed", meaning, action), tags=(tag,))
        report = (
            "DEPENDENCYGUARD RESULT\n\n"
            f"Status: {status}\n"
            f"Dependency: {dependency.name}\n"
            f"Version: {dependency.version or 'Not fixed'}\n"
            f"Ecosystem: {dependency.ecosystem}\n"
            f"Source file: {dependency.source_file}\n\n"
            f"WHAT THIS MEANS\n{meaning}\n\n"
            f"RECOMMENDED NEXT STEP\n{action}\n\n"
            f"ADDITIONAL DETAILS\n{details}"
        )
        self.row_details[row_id] = (report, notice_url)

    def show_results(self, dependencies: list[Dependency], findings: list[Finding], checked_online: bool) -> None:
        """Turn technical scan data into a single actionable result per dependency."""
        self.results.delete(*self.results.get_children())
        self.row_details.clear()
        findings_by_dependency: dict[tuple[str, str, str], list[Finding]] = {}
        for finding in findings:
            item = finding.dependency
            key = (item.name, item.version or "", item.source_file)
            findings_by_dependency.setdefault(key, []).append(finding)

        urgent, review, clear = 0, 0, 0
        for item in dependencies:
            key = (item.name, item.version or "", item.source_file)
            item_findings = findings_by_dependency.pop(key, [])
            known = [finding for finding in item_findings if finding.severity == "known"]
            unpinned = [finding for finding in item_findings if finding.severity == "medium"]
            information = [finding for finding in item_findings if finding.severity == "info"]
            source = f"Source file: {Path(item.source_file).name} | Package ecosystem: {item.ecosystem}."
            if known:
                advisory_list = ", ".join(finding.advisory for finding in known)
                details = "\n\n".join(finding.message for finding in known)
                self.add_result("Action needed", item, "A known security issue has been reported for this version.", "Open the security notice, update to a secure compatible version, then scan again.", "danger", f"{source}\n\nTechnical reference: {advisory_list}\n\n{details}", f"https://osv.dev/vulnerability/{known[0].advisory}")
                urgent += 1
            elif unpinned:
                self.add_result("Review needed", item, "The version is not fixed, so the installed package can change unexpectedly.", "Set an exact version in the dependency file, for example package==1.2.3.", "review", f"{source}\n\n{unpinned[0].message}")
                review += 1
            elif information:
                self.add_result("Online check pending", item, "The security database could not be reached for this package.", "Check your internet connection and run the online check again later.", "info", f"{source}\n\n{information[0].message}")
                review += 1
            elif checked_online:
                self.add_result("No known issue", item, "No known security issue was found for this exact version in the OSV database.", "Keep this dependency updated and run the check regularly.", "safe", f"{source}\n\nThis is not a guarantee that the package is safe. It means OSV has no known entry for this version.")
                clear += 1
            else:
                self.add_result("Not checked online", item, "Only a local scan was run; known security issues have not been checked yet.", "Click 'Check security issues online' to use the OSV database.", "info", source)

        for remaining in findings_by_dependency.values():
            finding = remaining[0]
            self.add_result("Review needed", finding.dependency, "A dependency file could not be fully read.", "Check the file format and run the scan again.", "review", finding.message)
            review += 1
        self.summary.set(f"Summary: {urgent} action needed  |  {review} review needed  |  {clear} with no known issue")
        self.status.set(f"Scan complete: {len(dependencies)} dependencies checked.")

    def show_selected_details(self, _event: object) -> None:
        """Show an explanation and an optional source link for the selected row."""
        selected = self.results.selection()
        if not selected:
            return
        details, notice_url = self.row_details[selected[0]]
        self.set_details(details)
        self.notice_button.configure(state="normal" if notice_url else "disabled")

    def set_details(self, details: str) -> None:
        """Place read-only, selectable text in the result detail area."""
        self.selected_details = details
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", details)
        self.details_text.configure(state="disabled")

    def copy_full_result(self) -> None:
        """Copy the complete selected result for sharing or follow-up support."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.selected_details)
        self.status.set("Full result copied to the clipboard. You can paste it into a message for support.")

    def copy_selected_text(self, _event: object) -> str:
        """Copy highlighted text, or the complete result when nothing is highlighted."""
        try:
            copied_text = self.details_text.get("sel.first", "sel.last")
        except self.tk.TclError:
            copied_text = self.selected_details
        self.root.clipboard_clear()
        self.root.clipboard_append(copied_text)
        self.status.set("Text copied to the clipboard.")
        return "break"

    def open_notice(self) -> None:
        """Open the selected OSV advisory in the default browser."""
        selected = self.results.selection()
        if selected:
            notice_url = self.row_details[selected[0]][1]
            if notice_url:
                webbrowser.open(notice_url)

    def show_help(self) -> None:
        """Explain the three result categories in non-technical language."""
        self.messagebox.showinfo(
            "Understanding the results",
            "Red – Action needed: A known security issue was reported for this package version. Open the security notice and update the package.\n\n"
            "Yellow – Review needed: The version is not fixed or a dependency file could not be read. Set an exact version or check the file.\n\n"
            "Green – No known issue: OSV has no known issue for this exact version. This is positive, but not a security guarantee.\n\n"
            "Blue – Not checked online: The scan was local only, or the security database was unavailable.\n\n"
            "Select a result to see a copyable report with the source file, explanation, and recommended next step."
        )

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
