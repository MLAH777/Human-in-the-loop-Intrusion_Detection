import time, json, random, os
LOG = "detections.json"
DOMAINS = ["google-login.com","update-paypal.net","secure-paypal.com","news.example.com","bank-secure.info"]
def push(d):
    try:
        a = json.load(open(LOG,"r"))
    except:
        a = []
    a.append(d)
    json.dump(a, open(LOG,"w"), indent=2)
while True:
    url = random.choice(DOMAINS)
    score = random.randint(0,8)
    if score >= 5 or "secure" in url or "login" in url:
        evt = {"tool":"phish","timestamp":time.time(),"src":"unknown","dst":"-","url":url,"heuristic_score":score}
        push(evt)
    time.sleep(10 + random.random()*5)
