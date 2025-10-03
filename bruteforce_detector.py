import time, json, random
LOG = "detections.json"
USERNAMES = ["root","admin","ubuntu","oracle","test"]
def push(d):
    try:
        a = json.load(open(LOG,"r"))
    except:
        a = []
    a.append(d)
    json.dump(a, open(LOG,"w"), indent=2)
while True:
    attempts = random.randint(1,20)
    ip = f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if attempts >= 5:
        evt = {"tool":"brute","timestamp":time.time(),"src":ip,"dst":"127.0.0.1","username":random.choice(USERNAMES),"attempts":attempts}
        push(evt)
    time.sleep(12 + random.random()*6)
