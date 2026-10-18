#!/usr/bin/env python

## Mysql-Python basic examples.
## All code is taken from [here](http://zetcode.com/databases/mysqlpythontutorial/)
## Gist created only for quick reference purpose

import sys
import _mysql

import MySQLdb as mdb

DB_HOST = 'localhost'
DB_USER = 'testuser'
DB_PASSWORD = 'test623'
DB_NAME = 'testdb'


def _mysql_get_version():
    """
    _mysql implements the mysql C api directly.
    Actually recommended to use MySQLdb which is a wrapper over _mysql module
    """
    con = None    
    try:
        con = _mysql.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)        
        con.query("SELECT VERSION()")
        result = con.use_result()
        print "MYSQL version: %s" % result.fetch_row()[0]
    except _mysql.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)        
    finally:
        if con:
            con.close()


def mdb_get_version():
    """
    Get the mysql version using the MySQLdb. Compatible with Python DB API which
    makes the code more portable
    """
    con = None
    try:
        con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    
        cur = con.cursor()
        cur.execute("SELECT VERSION()")
        data = cur.fetchone()
        print "Database version: %s" % data
        
    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)        
    finally:
        if con:
            con.close()


def create_and_populate():
    """
    Create a table for writers and insert some data into it
    """
    con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    
    with con:
        cur = con.cursor()
        sql = "CREATE TABLE writers (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(23))"
        cur.execute(sql)
        
        # insert some data
        writers = ['Jack London', 'Honore de Balzac', 'Lion Feuchtwanger', 'Emile Zola', 'Truman Capote']
        
        for name in writers:
            cur.execute("INSERT INTO writers (NAME) VALUES ('%s')" % name)


def retrieve_data():
    """
    Retrieve the data from the table.
    """
    con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    
    with con:
        cur = con.cursor()
        sql = "SELECT * FROM writers"
        cur.execute(sql)

        results = cur.fetchall()

        for r in results:
            print r


def retrieve_onebyone():
    """
    Retrieve data one row at a time instead of loading all results into memory at once
    """
    con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    
    with con:
        cur = con.cursor()
        sql = "SELECT * FROM writers"
        cur.execute(sql)

        numrows = int(cur.rowcount)

        for i in range(numrows):
            row = cur.fetchone()
            print "%d %s"  % (row[0], row[1])

        print "There are %d total writers in all" % numrows


def dict_cursor():
    """
    Retrieving data using a dict cursor instead of the default tuple cursor
    """
    con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    
    with con:
        cur = con.cursor(mdb.cursors.DictCursor)
        cur.execute("SELECT * FROM writers")

        results = cur.fetchall()

        for row in results:
            print "%d %s" % (row['id'], row['name'])


def with_description():
    """
    Retrieving the data and showing along with the column headers
    """
    con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)

    with con:
        cur = con.cursor()
        cur.execute("SELECT * FROM writers")
        results = cur.fetchall()
        description = cur.description

        print description
        print "%s %s" % (description[0][0], description[1][0])

        for row in results:
            print "%d %s" % row


def update_prep_stmt():
    """
    Using prepared statements to update the entries
    """
    con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)

    with con:
        cur = con.cursor()
        cur.execute("UPDATE writers SET name = %s WHERE id = %s",
                    ('Guy de Muapasant', 4))

        print "Number of rows updated: %d" % cur.rowcount


def with_transactions():
    """
    Rollback if any of the queries result in an error
    Only supported by Innodb engine.
    Notice writer instead of writers in the 3rd query
    """
    try:
    	con = mdb.connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
    	
    	cur = con.cursor()    	
    	cur.execute("UPDATE writers SET name = %s WHERE id = %s",
    	            ("Leo Tolstroy", 1))
    	cur.execute("UPDATE writers SET name = %s WHERE id = %s",
    	            ("Boris Pasternak", 2))
    	cur.execute("UPDATE writer SET name = %s WHERE id = %s",
    	            ("Leonid Leoniv", 3))
    	
    	con.commit()
    	con.close()
    except mdb.Error, e:
        print 'Time to Rollback..'
        con.rollback()
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)
    

if __name__ == '__main__':
    # _mysql_get_version()
    # mdb_get_version()
    # create_and_populate()
    # retrieve_data()
    # retrieve_onebyone()
    # dict_cursor()
    # with_description()
    # update_prep_stmt()
    # with_transactions()
    pass
