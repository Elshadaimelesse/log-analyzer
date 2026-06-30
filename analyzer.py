# analyzer.py — legacy entry point
# The project has been upgraded. Use main.py instead:
#   python main.py
#
# This file is kept for reference. All logic now lives in:
#   core/parser.py   — log parsing
#   core/detector.py — threat detection
#   core/reporter.py — output & reporting
#   main.py          — CLI entry point
#   dashboard.py     — Streamlit web dashboard

import subprocess, sys
subprocess.run([sys.executable, "main.py"] + sys.argv[1:])
