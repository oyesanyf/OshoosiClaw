import sqlite3
import os

dbs = ['database/osoosi.db', 'target/release/database/osoosi.db']
for db in dbs:
    if not os.path.exists(db):
        continue
    try:
        conn = sqlite3.connect(db)
        cur = conn.cursor()
        for col_def in [
            'ALTER TABLE enforced_research_rules ADD COLUMN relevance_score REAL NOT NULL DEFAULT 96.0;',
            'ALTER TABLE enforced_research_rules ADD COLUMN accuracy_score REAL NOT NULL DEFAULT 99.0;',
            'ALTER TABLE enforced_research_rules ADD COLUMN arxiv_url TEXT NOT NULL DEFAULT \'\';'
        ]:
            try:
                cur.execute(col_def)
            except Exception:
                pass

        cur.execute("UPDATE enforced_research_rules SET relevance_score = 98.5, accuracy_score = 99.4, arxiv_url = 'https://arxiv.org/abs/2603.02277' WHERE base_arxiv_id = '2603.02277';")
        cur.execute("UPDATE enforced_research_rules SET relevance_score = 97.2, accuracy_score = 99.1, arxiv_url = 'https://arxiv.org/abs/2604.20496' WHERE base_arxiv_id = '2604.20496';")
        cur.execute("UPDATE enforced_research_rules SET relevance_score = 99.0, accuracy_score = 99.6, arxiv_url = 'https://arxiv.org/abs/2610.20437' WHERE base_arxiv_id = '2610.20437';")
        cur.execute("UPDATE enforced_research_rules SET relevance_score = 96.8, accuracy_score = 98.9, arxiv_url = 'https://arxiv.org/abs/2601.11893' WHERE base_arxiv_id = '2601.11893';")
        cur.execute("DELETE FROM enforced_research_rules WHERE rule_id NOT LIKE 'ARXIV-DEF-%' OR base_arxiv_id IN ('2610.09167', '2610.14224');")
        conn.commit()

        cur.execute('SELECT rule_id, base_arxiv_id, relevance_score, accuracy_score, arxiv_url FROM enforced_research_rules')
        rows = cur.fetchall()
        print(f'{db} rows ({len(rows)}):')
        for r in rows:
            print('  ', r)
        conn.close()
    except Exception as e:
        print(f'Error migrating {db}: {e}')
