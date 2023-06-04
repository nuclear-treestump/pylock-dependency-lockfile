# PyLock Dependency Manager

## Introduction
Welcome to PyLock Dependency Manager, a personal project aimed at providing a simple and effective solution for managing Python dependencies. As the sole developer, progress might be slow but the goal is to create a tool that can accurately identify and track the dependencies of a Python script, and ensure that these dependencies are met before the script is executed.

## Current Capabilities
Currently, PyLock can:

- Parse a Python script and identify its direct dependencies.
- Check if the dependencies are installed and if their installed versions match the versions specified in the lockfile.
- Generate a lockfile that lists the script's dependencies along with metadata such as the author, home page, and summary.
- Execute the script only if all the dependencies are met.

## Goals
- **Avoid dependency hell:** By creating a lockfile that lists a script's dependencies along with their versions, PyLock ensures that you can always recreate the exact environment that the script needs to run.
- **Improve security:** By making sure that all dependencies are explicitly listed and their versions locked, PyLock helps avoid the risk of unintentionally installing malicious packages.
- **Facilitate sharing and collaboration:** The lockfile can be included when you share your script, allowing others to easily recreate your environment and run your script without any dependency issues.

**Note:** The current name of the project, "PyLock Dependency Manager", is a temporary placeholder and may be subject to change in the future.

## Roadmap
The planned enhancements for PyLock include:

1. **Improved Package Scanning:** PyLock will use static analysis to identify dependencies that are imported dynamically or conditionally.
2. **Dependency Graphs:** PyLock will generate visualizations of your project's dependency graph, helping you understand the relationships between various packages.
3. **Integration with Pip:** PyLock will integrate more closely with Pip, allowing it to automatically install any missing dependencies or update installed dependencies to the required versions.
4. **VSCode Extension:** A VSCode extension for PyLock is planned to provide real-time feedback on dependencies while writing code.
5. **CI/CD Pipeline Integration:** PyLock will provide functionality to be integrated into CI/CD pipelines for automatic dependency checking and resolution.
6. **Dependency Scanning via deps.dev:** Future versions of PyLock will integrate with deps.dev and other similar services to provide more detailed information about each dependency, including its popularity, development activity, and known security vulnerabilities.
7. **Virtual Environment Support:** PyLock plans to add functionality to spin up a virtual environment on the fly with the dependencies required in the version required for the script run.

## Feedback and Feature Requests
I am always open to feedback and suggestions. If you have ideas for new features or improvements, feel free to share them. However, please note that the decision to implement any proposed changes will be made at my discretion.

Stay tuned for updates as PyLock continues to evolve and improve!
