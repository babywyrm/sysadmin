#!/usr/bin/python3

################################
################################################

import pymysql


def execute(c, command):
    c.execute(command)
    return c.fetchall()


db = pymysql.connect(host='localhost',
                     port=3306,
                     user='root',
                     passwd='',
                     db='mysql')  # , charset='utf8')

c = db.cursor()

for table in execute(c, "show tables;"):
    table = table[0]
    cols = []
    for item in execute(c, "show columns from " + table + ";"):
        cols.append(item[0])
    data = execute(c, "select * from " + table + ";")
    with open("/tmp/mysql/" + table + ".csv", "w") as out:
        out.write("\t".join(cols) + "\n")
        for row in data:
            out.write("\t".join(str(el) for el in row) + "\n")
    print(table + ".csv written")
                                    
################################################
