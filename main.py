#main.py

# Made with ♥ by Ikari

import json
import os
import sys
import hashlib
import time
import pkg_resources
import subprocess
import logging
import argparse
import ast

def setup_logging(verbose=False):
    """
    Set up the logger. If verbose is True, the logger will output debug messages.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format='%(levelname)s: %(message)s', level=level)

def parse_arguments():
    """
    Parse command-line arguments. Returns an object containing the arguments.
    """
    parser = argparse.ArgumentParser(description="Check script dependencies using a lockfile")
    parser.add_argument('script_name', help="The name of the script to check dependencies for")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('-g', '--generate', action='store_true', help="Generate a lockfile if one doesn't exist")
    return parser.parse_args()

class DependencyLock:
    def __init__(self, script_name, generate_lockfile=False):
        self.script_name = script_name
        self.script_file = f"{script_name}.py"
        self.lockfile_name = script_name + '_dep.lck'
        self.lockfile = None
        self.should_generate_lockfile = generate_lockfile
        self.find_lockfile()

    def find_lockfile(self):
        """
        Attempt to open the lockfile for the given script. If the lockfile doesn't exist, 
        prompt the user to create one.
        """
        try:
            with open(self.lockfile_name, 'r') as f:
                self.lockfile = json.load(f)
        except FileNotFoundError:
            logging.info(f"No lockfile found for script {self.script_name}.")
            if self.should_generate_lockfile:
                self.generate_lockfile()
            else:
                sys.exit("No lockfile found. Exiting.")

    def generate_lockfile(self):
        """
        Generate a new lockfile for the script. The lockfile contains a list of all packages 
        imported by the script and information about each package, including its installed 
        version and availability in the system's Python environment.
        """
        deps = self.find_imports(self.script_file)
        deps_info = {}

        for dep in deps:
            deps_info[dep] = self.check_package_availability(dep)

        self.lockfile_content = {
            'meta': {
                'script': self.script_name,
                'hash': 'NYI, to be implemented later',
                'last_modified': int(os.path.getmtime(self.script_file))
            },
            'deps': deps_info
        }

        with open(self.lockfile_name, 'w') as f:
            json.dump(self.lockfile_content, f, indent=4)

        print(f"Generated new lockfile: {self.lockfile_name}")

    def find_imports(self, script_path):
        """
        Parse the Python script at the given path and return a list of all packages imported by the script.
        """
        with open(script_path, 'r') as script_file:
            script_code = script_file.read()

        module = ast.parse(script_code)
        imports = [node.names[0].name for node in ast.walk(module) if isinstance(node, (ast.Import, ast.ImportFrom))]

        return imports

    def read_lockfile(self):
        """
        Read the lockfile and check the availability of each package listed in it.
        If a package is not available, raise an exception. If a package is available, 
        but the installed version does not match the required version listed in the 
        lockfile, prompt the user whether to continue executing the script.
        """
        if not os.path.exists(self.lockfile_name):
            raise Exception(f"Lockfile {self.lockfile_name} does not exist.")

        with open(self.lockfile_name, 'r') as f:
            self.lockfile = json.load(f)

        for dep, info in self.lockfile['deps'].items():
            package_info = self.check_package_availability(dep, info['version'])
            availability = package_info['available']
            version_matches = package_info['version_matches']

            if not availability:
                raise Exception(f"Dependency {dep} is not available in the system's Python environment.")

            if version_matches is False:
                print(f"Dependency: {dep}, Version: {info['version']}, Available: {availability}, Version matches: {version_matches}")
                continue_script = input("Do you want to continue executing the script? (yes/no): ")
                if continue_script.lower() == 'yes':
                    self.execute_script(self.script_name)
                else:
                    raise Exception(f"Execution of script {self.script_name} stopped by user due to version mismatch in dependency {dep}.")


    def check_package_availability(self, package, version=None):
        """
        Check if a package is available in the system's Python environment. If the package is 
        available, check if its installed version matches the required version (if specified). 
        Returns a dictionary containing information about the package and its availability and version match status.
        """
        result = subprocess.run(['pip', 'show', package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode == 0:
            package_info = self.parse_package_info_from_pip_show(result.stdout.decode('utf-8'))
            installed_version = package_info.get('version', 'Version not specified')
            available = True
            version_matches = version is None or installed_version == version

            package_info.update({
                'available': available,
                'version_matches': version_matches
            })
        else:
            package_info = {
                'available': False,
                'version_matches': False
            }

        return package_info
    
    @staticmethod
    def parse_package_info_from_pip_show(output):
        """
        Parse the output of 'pip show <package>'. Returns a dictionary containing information 
        about the package.
        """
        package_info = {}
        for line in output.split('\n'):
            if ': ' in line:
                key, value = line.split(': ', 1)
                package_info[key.lower()] = value.rstrip('\r')
        return package_info


    def list_packages(self):
        """
        List all the packages specified in the lockfile along with their versions. This 
        method assumes that the lockfile exists and has been loaded into the self.lockfile 
        attribute.
        """
        if self.lockfile:
            print("Dependencies:")
            for dep, info in self.lockfile['deps'].items():
                required_version = info.get('version', 'Version not specified')
                package_info = self.check_package_availability(dep)
                installed_version = package_info.get('version', 'Not installed')

                print(f"+- {dep}")
                print(f"| +- Installed: {installed_version}")
                print(f"| +- Required: {required_version}")
        else:
            sys.exit("No lockfile to list packages from. Exiting.")


    def ask_user_confirmation(self):
        """
        Prompt the user to confirm whether they want to continue executing the script.
        Returns True if the user confirms, and False otherwise.
        """
        confirmation = input("Do you want to continue executing the script? (yes/no): ")
        return confirmation.lower() == "yes"


    def execute_script(self):
        script_path = self.script_file
        """
        Execute the Python script at the specified path. This method does not perform any 
        checks on the script or its dependencies.
        """
        process = subprocess.Popen(['python', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            output = process.stdout.readline()
            if output == b'' and process.poll() is not None:
                break
            if output:
                print(output.strip().decode())
        rc = process.poll()

        # Capture the standard error
        stderr = process.stderr.read().decode()
        if stderr:
            print(f"Script {script_path} failed to execute. Error: {stderr}")

        if rc == 0:
            print(f"Script {script_path} executed successfully.")
        else:
            print(f"Script {script_path} failed to execute with return code: {rc}")


def main():
    """
    Main function to orchestrate checking of script dependencies using a lockfile.
    """
    args = parse_arguments()
    setup_logging(args.verbose)

    logging.info(f"Checking dependencies for script {args.script_name}")
    dep_lock = DependencyLock(args.script_name, args.generate)

    dep_lock.find_lockfile()
    dep_lock.read_lockfile()

    # Check availability of all packages in the lockfile
    for package, info in dep_lock.lockfile['deps'].items():
        dep_lock.check_package_availability(package, info.get('version'))

    dep_lock.list_packages()

    if dep_lock.ask_user_confirmation():
        dep_lock.execute_script()

if __name__ == "__main__":
    main()
