
""" 
    These codes demonstrate how to connect a Python program to a MySQL Server using PyMySQL
    Note: You need to have a MySQL Server installed either the stand-alone MySQL Server or through XAMPP to test these programs
          You also need to run pip install pymysql if you don't have the module installed yet
"""

import pymysql
# Creation of PyMySQL Connection Object
try:
    conn = pymysql.connect(host="localhost",port=3306,db="mydb",user="root",password="")
except pymysql.MySQLError as e:
    print(e)
    sys.exit()
finally:
    print("Connection established sucessfully")
    conn.close() # You always have to close the connection
    

##########################################
##########################################

    
    """ 
    These codes demonstrate how to perform a simple SELECT SQL Command on a Python program using PyMySQL
    Note: You need to have a MySQL Server installed either the stand-alone MySQL Server or through XAMPP to test these programs
    You also need to run pip install pymysql if you don't have the module installed yet
"""

import pymysql
# Connection
conn = pymysql.connect(host="localhost",port=3306,db="mydb",user="root",password="")
print("Connection established sucessfully")

# Creation of a Cursor object
cursor = conn.cursor()
# Storing SQL Statements in a variable sql
sql = "SELECT * FROM students"
# Calling execute method
cursor.execute(sql)
# storing results in a result variable
result = cursor.fetchall() # fetchall retrieves all records
# Display the values
print(result) 
# Close the connection
cursor.close()
conn.close()


##########################################
##########################################

""" 
    These codes demonstrate an implementation of a class-based python sql controller object
    Note: You need to have a MySQL Server installed either the stand-alone MySQL Server or through XAMPP to test these programs
    You also need to run pip install pymysql if you don't have the module installed yet
    There is no error handling in this sample.
"""

from pymysql import *

class SQLController():
  def __init__(self, host="", port=0, db="",user="",password=""):
    """ Input parameters are host (string), port (integer), db (string), user (string), and password(can be left blank) (string) """
    self.host = host
    self.port = 0
    self.db = db
    self.user = ""
    self.password = ""
    self.sql = ""
  def select_all(self,table_name=""):
    """ Method for retrieving all values
        Input parameters are table_name (string) """
    self.conn = connect(host=self.host,port=self.port,db=self.db,user=self.user,password=self.password)
    self.cursor = self.conn.cursor()
    self.sql = "SELECT * FROM {}".format(table_name)
    self.cursor.execute(self.sql)
    self.result = self.cursor.fetchall()
    self.conn.close()
    return self.result

  def select_one(self,table_name=""):
    """ Method for retrieving all values
        Input parameters are table_name (string) """
    self.conn = connect(host=self.host,port=self.port,db=self.db,user=self.user,password=self.password)
    self.cursor = self.conn.cursor()
    self.sql = "SELECT * FROM {}".format(table_name)
    self.cursor.execute(self.sql)
    self.result = self.cursor.fetchone()
    self.conn.close()
    return self.result
  
  def update(self,table_name="",column_name="",new_value="",column_identifier="",identifer_value=""):
    """ Method for updating a table
        Input parameters are table_name (string) """
    self.conn = connect(host=self.host,port=self.port,db=self.db,user=self.user,password=self.password)
    self.cursor = self.conn.cursor()
    self.conn.begin() # begin transaction
    if type(new_value)==type(0) and type(identifer_value)==type(0):
      self.sql = "UPDATE {} SET {}={} WHERE {}={}".format(table_name,column_name,new_value,column_identifier,identifer_value)
    elif type(new_value)==type("") and type(identifer_value)==type(0):
      self.sql = "UPDATE {} SET {}='{}' WHERE {}={}".format(table_name,column_name,new_value,column_identifier,identifer_value)
    elif type(new_value)==type(0) and type(identifer_value)==type(""):
      self.sql = "UPDATE {} SET {}={} WHERE {}='{}'".format(table_name,column_name,new_value,column_identifier,identifer_value)
    elif type(new_value)==type("") and type(identifer_value)==type(""):
      self.sql = "UPDATE {} SET {}='{}' WHERE {}='{}'".format(table_name,column_name,new_value,column_identifier,identifer_value)
    self.cursor.execute(self.sql)
    self.conn.commit()
    self.conn.close()
    print("Query executed succesfully")
    return 0
    

##########################################
##########################################

