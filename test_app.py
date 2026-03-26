import os
os.environ["SECRET_KEY"] = "test123"

import app


def test_call_functions():
    for name in dir(app):
        obj = getattr(app, name)

        if callable(obj):
            try:
                obj()   # 👈 call function directly
            except:
                pass
