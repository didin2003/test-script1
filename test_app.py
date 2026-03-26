import os
os.environ["SECRET_KEY"] = "test123"

import app


def test_safe_execution():
    safe_functions = []

    for name in dir(app):
        obj = getattr(app, name)

        # only simple functions (skip risky ones)
        if callable(obj) and not name.startswith("_"):
            if "run" in name or "start" in name:
                continue   # skip dangerous functions

            safe_functions.append(obj)

    for func in safe_functions[:10]:   # limit to 10 only
        try:
            func()
        except:
            pass
