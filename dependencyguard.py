"""DependencyGuard - erster Schritt zur Dependency-Pruefung.

PSEUDOCODE:
1. Bestimme den Ordner, der untersucht werden soll.
2. Suche dort nach bekannten Dependency-Dateien.
3. Ordne jede gefundene Datei ihrer Programmiersprache zu.
4. Zeige die Ergebnisse klar an.
5. Spaeter: Lies Dependencies aus und pruefe Sicherheitswarnungen.
"""

from pathlib import Path


# Diese Dateien enthalten Abhaengigkeiten der Sprachen, die DependencyGuard
# zuerst unterstuetzen soll. Weitere Dateinamen kommen spaeter hinzu.
DEPENDENCY_FILES = {
    "Python": ("requirements.txt", "pyproject.toml", "Pipfile"),
    "JavaScript/TypeScript": ("package.json",),
    "Java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "Go": ("go.mod",),
}


def find_dependency_files(project_folder: Path) -> list[tuple[str, Path]]:
    """Return supported dependency files found directly in a project folder."""
    found_files = []

    for language, file_names in DEPENDENCY_FILES.items():
        for file_name in file_names:
            dependency_file = project_folder / file_name
            if dependency_file.is_file():
                found_files.append((language, dependency_file))

    return found_files


def main() -> None:
    """Run the first local check in the folder containing this file."""
    project_folder = Path(__file__).resolve().parent
    found_files = find_dependency_files(project_folder)

    print("DependencyGuard - Dependency-Dateien suchen")
    print(f"Projektordner: {project_folder}")

    if not found_files:
        print("Keine unterstuetzten Dependency-Dateien gefunden.")
        return

    print("Gefundene Dateien:")
    for language, dependency_file in found_files:
        print(f"- {language}: {dependency_file.name}")


if __name__ == "__main__":
    main()
