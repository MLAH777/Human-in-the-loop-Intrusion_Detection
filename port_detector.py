import socket, time, json, os, random
LOG = "detections.json"
TARGET = "127.0.0.1"
PORTS = [22,80,443,8000,9999]
def push(d):
    try:
        a = json.load(open(LOG,"r"))
    except:
        a = []
    a.append(d)
    json.dump(a, open(LOG,"w"), indent=2)
while True:
    for p in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            r = s.connect_ex((TARGET,p))
            is_open = (r==0)
        except:
            is_open = False
        finally:
            s.close()
        if is_open:
            evt = {"tool":"port","timestamp":time.time(),"src":"unknown","dst":TARGET,"port":p}
            push(evt)
    time.sleep(8 + random.random()*4)
