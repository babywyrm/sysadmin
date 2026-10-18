from flask import Flask, render_template
import pymysql

app = Flask(__name__)


class Database:
    def __init__(self):
        host = "127.0.0.1"
        user = "test"
        password = "password"
        db = "employees"

        self.con = pymysql.connect(host=host, user=user, password=password, db=db, cursorclass=pymysql.cursors.
                                   DictCursor)
        self.cur = self.con.cursor()

    def list_employees(self):
        self.cur.execute("SELECT first_name, last_name, gender FROM employees LIMIT 50")
        result = self.cur.fetchall()

        return result

@app.route('/')
def employees():

    def db_query():
        db = Database()
        emps = db.list_employees()

        return emps

    res = db_query()

    return render_template('employees.html', result=res, content_type='application/json')
