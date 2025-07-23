from pydepguardnext.bootstrap import boot
boot.run_boot()
from pydepguardnext.cli.main import main_cli_input
from pydepguardnext.bootstrap import clock
from pydepguardnext.bootstrap.boot import JIT_DATA_BUNDLE

if __name__ == "__main__":
    print("RUNNING AS SCRIPT")
    print("EXITING MAIN")
    from sys import executable
    from os import environ
    print("ENVIRONMENT VARIABLES:")
    for k, v in environ.items():
        print(f"{k}={v}")
    print("PYTHON EXECUTABLE:", executable)
    main_cli_input()