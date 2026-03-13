import sqlite3

conn = sqlite3.connect("softnet_guard.db")

conn.execute("DELETE FROM devices WHERE ip_address LIKE '10.82.%'")
conn.execute("DELETE FROM traffic_stats WHERE ip_address LIKE '10.82.%'")
conn.commit()
conn.close()

print("Old college network data cleared.")