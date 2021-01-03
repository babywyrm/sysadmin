## https://gist.github.com/pdxjohnny/9d0c7c87d2c8fd70854d
##############

import MySQLdb

db_config = {
	"host":"localhost",
	"username":"username",
	"password":"password",
	"name":"name_of_database"
}

def query( query, bindings = False ):
	con = MySQLdb.connect( db_config['host'], db_config['username'], db_config['password'], db_config['name'] )
	if con:
		curs = con.cursor(MySQLdb.cursors.DictCursor)
		if not bindings:
			curs.execute(query)
		else:
			curs.execute(query, bindings)
		con.commit()
		res = curs.fetchall()
		if len(res) < 1:
			return False
		return res

def insert( query, bindings = False ):
	con = MySQLdb.connect( db_config['host'], db_config['username'], db_config['password'], db_config['name'] )
	if con:
		curs = con.cursor(MySQLdb.cursors.DictCursor)
		if not bindings:
			curs.execute(query)
		else:
			curs.execute(query, bindings)
		con.commit()
		return curs.lastrowid

def save( obj ):
	to_return = False
	if 'id' in obj or 'name' in obj:
		values = [ item[1] for item in obj.items() ]
		values = tuple( values )
		run_query = "REPLACE INTO `actions` "
		run_query += "( `" + "`, `".join( obj.keys() ) + "` ) "
		run_query += "VALUES ( "
		run_query += '%s, ' * len( obj )
		run_query = run_query[:-2] + " )"
		try:
			print run_query, values
			to_return = insert( run_query, values )
		except Exception, e:
			print e
	return to_return
