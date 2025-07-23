from uuid import uuid4

def get_uuid() -> str:
    # This makes UUIDs. Isn't that great?
    # If I have to explain this, you probably shouldn't be using this library.
    return str(uuid4())

