import logging

def config(policy="strict", fill_missing=True, venv=1, nx=True, os_check=True):
    logging.basicConfig(level=logging.INFO)
    logging.info(f"PyLock Configured: policy={policy}, fill_missing={fill_missing}, venv={venv}, nx={nx}, os_check={os_check}")

    