#!/usr/bin/env python3
"""10 · AI THREAT PREDICTOR — ML-based anomaly scoring (no external ML libs)"""

import math, json, argparse, random
from collections import defaultdict
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.MAGENTA}╔══════════════════════════════════════╗\n║  🤖 AI THREAT PREDICTOR  v1.0        ║\n║  Statistical anomaly scoring         ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

class NaiveBayesThreatClassifier:
    """Simple Naive Bayes classifier for threat detection."""
    def __init__(self):
        self.class_counts  = defaultdict(int)
        self.feature_counts= defaultdict(lambda: defaultdict(int))
        self.total         = 0

    def train(self, features: dict, label: str):
        self.class_counts[label] += 1
        self.total += 1
        for k, v in features.items():
            self.feature_counts[label][f"{k}={v}"] += 1

    def predict(self, features: dict) -> tuple:
        scores = {}
        for label, count in self.class_counts.items():
            log_prob = math.log(count / self.total)
            for k, v in features.items():
                feat_count = self.feature_counts[label].get(f"{k}={v}", 0) + 1
                log_prob  += math.log(feat_count / (count + 10))
            scores[label] = log_prob
        best = max(scores, key=scores.get)
        total_exp = sum(math.exp(s) for s in scores.values())
        confidence= math.exp(scores[best]) / total_exp if total_exp > 0 else 0
        return best, round(confidence * 100, 1)

class AnomalyScorer:
    """Z-score based anomaly detection."""
    def __init__(self):
        self.baselines = {}

    def establish_baseline(self, metric: str, values: list):
        if not values: return
        mean   = sum(values) / len(values)
        variance = sum((x-mean)**2 for x in values) / len(values)
        stddev = math.sqrt(variance)
        self.baselines[metric] = {"mean":mean,"std":stddev}

    def score(self, metric: str, value: float) -> float:
        if metric not in self.baselines: return 0.0
        b   = self.baselines[metric]
        std = b["std"] if b["std"] > 0 else 1
        return abs((value - b["mean"]) / std)

    def is_anomaly(self, metric: str, value: float, threshold: float = 3.0) -> bool:
        return self.score(metric, value) > threshold

def build_trained_classifier() -> NaiveBayesThreatClassifier:
    clf = NaiveBayesThreatClassifier()
    training_data = [
        ({"port":"22","failed_logins":"high","time":"night","country":"CN"}, "brute_force"),
        ({"port":"22","failed_logins":"high","time":"day","country":"RU"},   "brute_force"),
        ({"port":"80","payload":"sql","method":"GET","ua":"sqlmap"},          "sqli"),
        ({"port":"80","payload":"script","method":"GET","ua":"Mozilla"},      "xss"),
        ({"port":"443","payload":"../","method":"GET","ua":"curl"},           "path_traversal"),
        ({"port":"80","failed_logins":"low","time":"day","country":"CO"},     "normal"),
        ({"port":"443","failed_logins":"none","time":"day","country":"US"},   "normal"),
        ({"port":"22","failed_logins":"none","time":"day","country":"CO"},    "normal"),
        ({"port":"4444","payload":"none","method":"CONNECT","ua":"nc"},       "backdoor"),
        ({"port":"6379","payload":"none","method":"DIRECT","ua":"redis-cli"}, "unauthorized_access"),
        ({"port":"27017","payload":"none","method":"DIRECT","ua":"mongo"},    "unauthorized_access"),
    ]
    for features, label in training_data:
        clf.train(features, label)
    return clf

def analyze_event(event: dict, clf: NaiveBayesThreatClassifier,
                   scorer: AnomalyScorer) -> dict:
    features = {
        "port":         str(event.get("port","80")),
        "payload":      event.get("payload","none"),
        "method":       event.get("method","GET"),
        "ua":           event.get("user_agent","Mozilla")[:20].lower(),
        "failed_logins":event.get("failed_logins","none"),
        "country":      event.get("country","??"),
        "time":         "night" if int(datetime.now().strftime("%H")) < 7 or
                                   int(datetime.now().strftime("%H")) > 22 else "day",
    }
    threat_type, confidence = clf.predict(features)
    anomaly_score = scorer.score("requests_per_min",
                                   event.get("requests_per_min", 10))
    return {
        "event":         event,
        "threat_type":   threat_type,
        "confidence":    confidence,
        "anomaly_score": round(anomaly_score, 2),
        "risk":          "CRÍTICO" if confidence > 80 and threat_type != "normal"
                         else "ALTO" if confidence > 60 and threat_type != "normal"
                         else "MEDIO" if threat_type != "normal"
                         else "BAJO",
    }

def demo_analysis():
    clf    = build_trained_classifier()
    scorer = AnomalyScorer()
    scorer.establish_baseline("requests_per_min",
                               [random.gauss(50,15) for _ in range(100)])

    events = [
        {"src_ip":"45.33.32.156","port":22,"failed_logins":"high","payload":"none",
         "method":"SSH","user_agent":"paramiko","country":"CN","requests_per_min":150},
        {"src_ip":"203.0.113.5", "port":80,"failed_logins":"none","payload":"sql",
         "method":"GET","user_agent":"sqlmap/1.7","country":"RU","requests_per_min":200},
        {"src_ip":"10.0.0.50",   "port":443,"failed_logins":"none","payload":"none",
         "method":"GET","user_agent":"Mozilla/5.0","country":"CO","requests_per_min":45},
        {"src_ip":"198.51.100.1","port":4444,"failed_logins":"none","payload":"none",
         "method":"CONNECT","user_agent":"nc","country":"??","requests_per_min":300},
        {"src_ip":"192.0.2.10",  "port":80,"failed_logins":"none","payload":"script",
         "method":"GET","user_agent":"Mozilla/5.0","country":"BR","requests_per_min":30},
    ]

    print(f"\n{Fore.CYAN}[*] Analizando {len(events)} eventos con ML...\n")
    for result in [analyze_event(e, clf, scorer) for e in events]:
        risk_c = {
            "CRÍTICO":Fore.RED,"ALTO":Fore.RED,
            "MEDIO":Fore.YELLOW,"BAJO":Fore.GREEN
        }.get(result["risk"], Fore.WHITE)
        e = result["event"]
        print(f"  {risk_c}[{result['risk']}]{Style.RESET_ALL} "
              f"{e['src_ip']:<18} "
              f"{Fore.YELLOW}{result['threat_type']:<20}{Style.RESET_ALL} "
              f"Conf: {result['confidence']}%  "
              f"Anomaly: {result['anomaly_score']}σ")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="AI Threat Predictor")
    parser.add_argument("--demo",  action="store_true", default=True)
    parser.add_argument("--event", nargs="+", help="port=80 payload=sql country=RU")
    args = parser.parse_args()

    clf    = build_trained_classifier()
    scorer = AnomalyScorer()
    scorer.establish_baseline("requests_per_min",[random.gauss(50,15) for _ in range(100)])

    if args.event:
        event = {}
        for item in args.event:
            if "=" in item:
                k,v = item.split("=",1)
                event[k] = v
        result = analyze_event(event, clf, scorer)
        print(f"\n  Threat   : {result['threat_type']}")
        print(f"  Confidence: {result['confidence']}%")
        print(f"  Risk     : {result['risk']}")
    else:
        demo_analysis()

if __name__ == "__main__":
    main()
