import subprocess, time, os, sys
p1 = subprocess.Popen([sys.executable, "port_detector.py"])
p2 = subprocess.Popen([sys.executable, "phishing_detector.py"])
p3 = subprocess.Popen([sys.executable, "bruteforce_detector.py"])
print("Detectors started. Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    p1.terminate(); p2.terminate(); p3.terminate()
    print("Stopped.")
