# ROADMAP

The following roadmap outlines the features that are planned for future versions of PyLock Dependency Manager. Note that this roadmap is subject to change and is not a guarantee of any specific feature's inclusion in the project.

## Version 1.0
- Initial release.
- Basic functionality for creating a lockfile with a script's direct dependencies and their versions.
- Ability to check whether the required dependencies for a script are installed and at the correct versions.

## Version 2.0
- Ability to handle multiple scripts, treating them as a single project.
- Recursive script checking to capture both direct and indirect dependencies.
- Support for creating a virtual environment (venv) with the necessary dependencies installed.
- Collection of basic OS information to aid in dependency resolution.
- Logging of sub-dependencies in addition to direct dependencies.

## Version 3.0
- Extension for Visual Studio Code to provide dependency information directly in the editor.
- Integration with CI/CD pipelines for automated dependency checking.
- Functionality for scanning dependencies via [Deps.dev](https://deps.dev/) and other sources of package information.
- Module version that can be imported and used within other Python scripts.

## Version 4.0
- Advanced project management features, including handling multi-script projects and creating a project-wide lockfile.
- Secure database for tracking dependencies across multiple scripts and projects, with user-responsible security.

Please note that the project's name, "PyLock Dependency Manager," is temporary and may change in the future. As of now, PyLock is being developed by a single developer, so progress may be slow at times. Your patience and support are appreciated!
