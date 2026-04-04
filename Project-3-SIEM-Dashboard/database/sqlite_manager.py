import sqlite3
import json

class DatabaseManager:
    """SIEM loglarını ve alarmlarını SQLite üzerinde tutan modül."""
    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS events
                     (event_id TEXT PRIMARY KEY, timestamp TEXT, source_type TEXT, 
                      src_ip TEXT, dst_ip TEXT, action TEXT, severity TEXT, user TEXT, msg TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts
                     (alert_id TEXT PRIMARY KEY, timestamp TEXT, rule_name TEXT, 
                      description TEXT, severity TEXT, event_count INTEGER, source_event_ids TEXT)''')
        
        c.execute('''CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp)''')
        self.conn.commit()

    def insert_event(self, event: dict):
        c = self.conn.cursor()
        c.execute('''INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)''', 
                  (event.get('event_id'), event.get('timestamp'), event.get('source_type'), 
                   event.get('src_ip'), event.get('dst_ip'), event.get('action'), 
                   event.get('severity'), event.get('user'), event.get('msg')))
        self.conn.commit()

    def insert_alert(self, alert: dict):
        c = self.conn.cursor()
        c.execute('''INSERT INTO alerts VALUES (?,?,?,?,?,?,?)''',
                  (alert.get('alert_id'), alert.get('timestamp'), alert.get('rule_name'),
                   alert.get('description'), alert.get('severity'), alert.get('event_count'),
                   json.dumps(alert.get('source_event_ids', []))))
        self.conn.commit()

    def get_recent_events(self, limit=100):
        c = self.conn.cursor()
        c.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
        columns = [col[0] for col in c.description]
        return [dict(zip(columns, row)) for row in c.fetchall()]
        
    def get_recent_alerts(self, limit=50):
        c = self.conn.cursor()
        c.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
        columns = [col[0] for col in c.description]
        return [dict(zip(columns, row)) for row in c.fetchall()]
