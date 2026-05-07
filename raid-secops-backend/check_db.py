import psycopg2

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    database="RAID-SecOps",
    user="postgres",
    password="raid"
)
cur = conn.cursor()
cur.execute("SELECT sample_id FROM alerts WHERE sample_id LIKE 'SPL-GEN2%' ORDER BY sample_id DESC LIMIT 5")
rows = cur.fetchall()
if rows:
    print("Last 5 GEN2 alerts in database:")
    for r in rows:
        print(" ", r[0])
else:
    print("No GEN2 alerts found")

cur.execute("SELECT COUNT(*) FROM alerts")
total = cur.fetchone()[0]
print(f"\nTotal alerts in database: {total}")
cur.close()
conn.close()
