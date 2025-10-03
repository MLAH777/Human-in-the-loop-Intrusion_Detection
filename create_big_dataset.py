import pandas as pd, random
OUT = "big_threat_dataset.csv"
COLUMNS = ["AttackType","SourceIP","DestIP","Port","URL/Domain","Username","Attempts","HumanDecision","HumanReason"]
def generate():
    rows = []
    private_ips = [f"192.168.1.{i}" for i in range(2,120)]
    pub_ips = [f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(150)]
    ports = [22,21,23,80,443,3389,3306,8080]
    safe_sites = ["google.com","microsoft.com","amazon.com","wikipedia.org","github.com"]
    for ip in private_ips[:80]:
        rows.append({"AttackType":"Safe","SourceIP":ip,"DestIP":"192.168.1.100","Port":"-","URL/Domain":"-","Username":"-","Attempts":"-","HumanDecision":"Safe","HumanReason":"-"})
    for s in safe_sites:
        rows.append({"AttackType":"Safe","SourceIP":"-","DestIP":"-","Port":"-","URL/Domain":s,"Username":"-","Attempts":"-","HumanDecision":"Safe","HumanReason":"-"})
    for p in ports:
        rows.append({"AttackType":"PortScan","SourceIP":random.choice(pub_ips),"DestIP":random.choice(private_ips),"Port":str(p),"URL/Domain":"-","Username":"-","Attempts":"-","HumanDecision":"Prevent" if p in (21,23,3389) else "Safe","HumanReason":"Open admin-like service" if p in (21,23,3389) else "-"})
    phish = ["secure-google-login.com","paypal-update.net","free-gift.online","bank-login.verify"]
    for d in phish:
        rows.append({"AttackType":"Phishing","SourceIP":"-","DestIP":"-","Port":"-","URL/Domain":d,"Username":"-","Attempts":"-","HumanDecision":"Prevent","HumanReason":"Suspicious phishing-like domain"})
    for _ in range(80):
        rows.append({"AttackType":"BruteForce","SourceIP":random.choice(pub_ips),"DestIP":random.choice(private_ips),"Port":"22","URL/Domain":"-","Username":random.choice(["root","admin","test"]),"Attempts":str(random.randint(6,30)),"HumanDecision":"Prevent","HumanReason":"Repeated failed logins"})
    df = pd.DataFrame(rows, columns=COLUMNS)
    df.to_csv(OUT, index=False)
    print("Created", OUT)
if __name__ == "__main__":
    generate()
