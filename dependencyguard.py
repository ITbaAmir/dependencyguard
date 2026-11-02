"""DependencyGuard - first step towards dependency checking.

PSEUDOCODE:
1. Identify the folder to inspect.
2. Search the folder for known dependency files.
3. Match every found file to its programming language.
4. Display the results clearly.
5. Later: Read dependencies and check security advisories.
"""

from pathlib import Path


# These files contain dependencies for the languages that DependencyGuard
# will support first. More file names will be added later.
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

    print("DependencyGuard - Finding dependency files")
    print(f"Project folder: {project_folder}")

    if not found_files:
        print("No supported dependency files found.")
        return

    print("Found files:")
    for language, dependency_file in found_files:
        print(f"- {language}: {dependency_file.name}")


if __name__ == "__main__":
    main()
