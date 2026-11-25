"""SQLite storage for alerts and per-alert chat history."""
import json
import os
import sqlite3
import threading


class AlertStorage:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT, src TEXT, dst TEXT, protocol TEXT, label TEXT,
                confidence REAL, is_attack INTEGER, is_anomaly INTEGER,
                anomaly_score REAL, top_features TEXT
            );
            CREATE TABLE IF NOT EXISTS chat(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER, role TEXT, content TEXT
            );
            """)
            self.conn.commit()

    @staticmethod
    def _alert(row):
        d = dict(row)
        d["top_features"] = json.loads(d.get("top_features") or "[]")
        d["is_attack"] = bool(d["is_attack"])
        d["is_anomaly"] = bool(d["is_anomaly"])
        return d

    def save_alert(self, e):
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO alerts(time,src,dst,protocol,label,confidence,is_attack,"
                "is_anomaly,anomaly_score,top_features) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (e["time"], e["src"], e["dst"], e["protocol"], e["label"],
                 e["confidence"], int(e["is_attack"]), int(e["is_anomaly"]),
                 e["anomaly_score"], json.dumps(e["top_features"])),
            )
            self.conn.commit()
            return cur.lastrowid

    def get_all_alerts(self, limit=200):
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._alert(r) for r in rows]

    def get_alert_by_id(self, aid):
        with self.lock:
            row = self.conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return self._alert(row) if row else None

    def count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def get_chat_history(self, aid):
        with self.lock:
            rows = self.conn.execute(
                "SELECT role, content FROM chat WHERE alert_id=? ORDER BY id", (aid,)
            ).fetchall()
        return [dict(r) for r in rows]

    def save_chat_message(self, aid, role, content):
        with self.lock:
            self.conn.execute(
                "INSERT INTO chat(alert_id, role, content) VALUES (?,?,?)",
                (aid, role, content),
            )
            self.conn.commit()

    def clear_all(self):
        with self.lock:
            self.conn.executescript("DELETE FROM alerts; DELETE FROM chat;")
            self.conn.commit()