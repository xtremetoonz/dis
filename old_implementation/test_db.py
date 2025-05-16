import mysql.connector

def test_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="dis_user",
            password="tv6LhpUq_ytcU9@o2g93",
            database="dis_database"
        )
        print("Database connection successful!")
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES")
        print("\nExisting tables:")
        for table in cursor:
            print(table[0])
        conn.close()
    except mysql.connector.Error as err:
        print(f"Error: {err}")

if __name__ == "__main__":
    test_connection()
