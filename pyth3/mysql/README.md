

OBVI CHUNKS.
<br>
<br>


Determine schema.

.....................
.....................
<br>
<br>



import mysql.connector

try:
    connection = mysql.connector.connect(host='localhost',
                                         database='electronics',
                                         user='pynative',
                                         password='pynative@#29')

    mySql_insert_query = """INSERT INTO logger (Id, Name, Price, Purchase_date) 
                           VALUES 
                           (15, 'Lenovo ThinkPad P71', 6459, '2019-08-14') """

    cursor = connection.cursor()
    cursor.execute(mySql_insert_query)
    connection.commit()
    print(cursor.rowcount, "Record inserted successfully into logger table")
    cursor.close()

except mysql.connector.Error as error:
    print("Failed to insert record into logger table {}".format(error))

finally:
    if connection.is_connected():
        connection.close()
        print("MySQL connection is closed")
        

<br>
<br>
.....................
.....................
