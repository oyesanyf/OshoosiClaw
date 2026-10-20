import sqlite3

for db_path in ['database/osoosi.db', 'target/release/database/osoosi.db']:
    print(f"=== {db_path} ===")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM threats")
    count = cur.fetchone()[0]
    print(f"Row count: {count}")
    cur.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='threats'")
    indices = cur.fetchall()
    print("Indices:", indices)
    conn.close()
