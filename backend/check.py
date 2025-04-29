
import MySQLdb
try:
    db = MySQLdb.connect(
        host="giri29.mysql.pythonanywhere-services.com",
        user="giri29",
        passwd="Rk5Y:H-K8zwf8nj",
        db="giri29$job_database",
    )
    print("Connection successful!")
except Exception as e:
    print("Failed to connect:", e)
