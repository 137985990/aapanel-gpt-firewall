import json
import time
from pathlib import Path


class BanStore:
    def __init__(self, rule_path, meta_path=None, now_fn=None):
        self.rule_path = Path(rule_path)
        self.meta_path = Path(meta_path) if meta_path else None
        self.now_fn = now_fn or (lambda: int(time.time()))

    def load_rules(self):
        if not self.rule_path.exists():
            return []
        body = self.rule_path.read_text()
        if not body.strip():
            return []
        return json.loads(body)

    def save_rules(self, rules):
        self.rule_path.write_text(json.dumps(rules, separators=(",", ":")))

    def _ip_to_arr(self, ip):
        parts = ip.split(".")
        if len(parts) != 4:
            raise ValueError("invalid ip")
        nums = [int(p) for p in parts]
        if any(v < 0 or v > 255 for v in nums):
            raise ValueError("invalid ip")
        return nums

    def _is_exact(self, rule):
        return len(rule) >= 2 and rule[0] == rule[1]

    def _is_expired(self, rule, now):
        return len(rule) >= 3 and int(rule[2]) > 0 and int(rule[2]) <= now

    def prune_and_migrate(self, default_seconds=28800):
        now = int(self.now_fn())
        changed = False
        new_rules = []
        for rule in self.load_rules():
            if self._is_expired(rule, now):
                changed = True
                continue
            if len(rule) < 3 and self._is_exact(rule):
                rule = [rule[0], rule[1], now + int(default_seconds)]
                changed = True
            new_rules.append(rule)
        if changed:
            self.save_rules(new_rules)
        return changed

    def active_exact_ips(self):
        now = int(self.now_fn())
        result = []
        for rule in self.load_rules():
            if self._is_expired(rule, now):
                continue
            if self._is_exact(rule):
                result.append(".".join(map(str, rule[0])))
        return result

    def add_temp_ban(self, ip, seconds, reason="manual_temp"):
        ipn = self._ip_to_arr(ip)
        now = int(self.now_fn())
        rules = []
        for rule in self.load_rules():
            if self._is_expired(rule, now):
                continue
            if self._is_exact(rule) and rule[0] == ipn:
                return False
            rules.append(rule)
        rules.insert(0, [ipn, ipn, now + int(seconds)])
        self.save_rules(rules)
        return True

    def remove_exact_ip(self, ip):
        ipn = self._ip_to_arr(ip)
        removed = False
        new_rules = []
        for rule in self.load_rules():
            if self._is_exact(rule) and rule[0] == ipn:
                removed = True
                continue
            new_rules.append(rule)
        if removed:
            self.save_rules(new_rules)
        return removed

    def clear_exact_ips(self):
        removed = 0
        new_rules = []
        for rule in self.load_rules():
            if self._is_exact(rule):
                removed += 1
                continue
            new_rules.append(rule)
        if removed:
            self.save_rules(new_rules)
        return removed
