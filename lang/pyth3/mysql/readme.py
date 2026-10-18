

##
####################


import mysql.connector

try:
    connection = mysql.connector.connect(host='localhost',
                                         database='electronics',
                                         user='pynative',
                                         password='pynative@#29')

    mySql_insert_query = """INSERT INTO Laptop (Id, Name, Price, Purchase_date) 
                           VALUES 
                           (15, 'Lenovo ThinkPad P71', 6459, '2019-08-14') """

    cursor = connection.cursor()
    cursor.execute(mySql_insert_query)
    connection.commit()
    print(cursor.rowcount, "Record inserted successfully into Laptop table")
    cursor.close()

except mysql.connector.Error as error:
    print("Failed to insert record into Laptop table {}".format(error))

finally:
    if connection.is_connected():
        connection.close()
        print("MySQL connection is closed")


####################
####################


import MySQLdb as db
import os

# MySQL configurations
MYSQL_USER = os.environ['MYSQL_USER']
MYSQL_PASSWORD = os.environ['MYSQL_PASSWORD']
MYSQL_HOST = os.environ['MYSQL_HOST']
MYSQL_DATABASE = os.environ['MYSQL_DATABASE']

print(MYSQL_USER)
print(MYSQL_PASSWORD)
print(MYSQL_HOST)
print(MYSQL_DATABASE)

def main():
    conn = db.connect(
            user=MYSQL_USER,
            passwd=MYSQL_PASSWORD,
            host=MYSQL_HOST,
            db=MYSQL_DATABASE
        )
    c = conn.cursor()

    sql = 'drop table if exists test'
    c.execute(sql)

    sql = 'create table test (id int, content varchar(32))'
    c.execute(sql)

    sql = 'show tables'
    c.execute(sql)
    print('===== table list =====')
    print(c.fetchone())

    # insert records
    sql = 'insert into test values (%s, %s)'
    c.execute(sql, (1, 'hoge'))

    datas = [
        (2, 'foo'),
        (3, 'bar')
    ]
    c.executemany(sql, datas)

    # select records
    sql = 'select * from test'
    c.execute(sql)
    print('===== Records =====')
    for row in c.fetchall():
        print('Id:', row[0], 'Content:', row[1])

    conn.commit()
    c.close()
    conn.close()


if __name__ == '__main__':
    main()
    
    
####################
## 
