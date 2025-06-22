
import requests
import pandas as pd
from datetime import datetime
from pathlib import Path
from math import sqrt
import importlib
from sqlalchemy import create_engine
import yaml
import fastapi
from pydantic import BaseModel
from importlib import metadata

pd.DataFrame({"A": [1, 2]}).to_excel("fake.xlsx", index=False)

Path("example.yml").write_text("key: value\n")


mod = importlib.import_module("json")

print("Running real_script.py")
print("Today is", datetime.now().isoformat())

pd.read_excel("fake.xlsx") 
pd.read_html("<table><tr><td>1</td></tr></table>") 

engine = create_engine("sqlite:///example.db")

with open("example.yml") as f:
    data = yaml.safe_load(f)

class MyModel(BaseModel):
    name: str

app = fastapi.FastAPI()

@app.get("/")
def read_root():
    return {"message": "Daisy.. Daisy.. give me your answer do.."}  

daisy = read_root()
print("HAL says:", daisy["message"])

dists = metadata.distributions()
for dist in dists:
    print(f"Package: {dist.metadata['Name']}, Version: {dist.version}")
