import sys
import os

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root)

def test_import():
    import sauce_connect
