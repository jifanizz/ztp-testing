#! /usr/bin/env python3

import uvicorn
from app.main import api

# Just for testing purposes. In production use uvicorn directly.
# Example: % uvicorn app.main:api --host 0.0.0.0 --port 8080
if __name__ == "__main__":
    uvicorn.run(api, host="127.0.0.1", port=8080)
