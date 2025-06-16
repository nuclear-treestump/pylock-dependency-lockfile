KNOWN_DEP_MAP = {
  "yaml": "pyyaml",
  "bs4": "beautifulsoup4",
  "cv2": "opencv-python",
  "PIL": "pillow",
  "sklearn": "scikit-learn",
  "Crypto": "pycryptodome",
  "Image": "pillow",
  "lxml": "lxml",
  "win32com": "pywin32"
}

KNOWN_TRANSITIVE = {
    "pandas.read_excel": ["openpyxl", "xlrd"],
    "pandas.read_html": ["lxml", "html5lib", "bs4"],
    "sqlalchemy.create_engine": ["sqlite3", "psycopg2", "mysqlclient"],
    "yaml.safe_load": ["pyyaml"],
    "matplotlib.use": ["matplotlib"],
    "pydantic.BaseModel": ["pydantic"],
}