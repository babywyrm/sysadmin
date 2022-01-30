
#!/usr/bin/python3

############ chiv/jack
############ hackthebox.com/$$SPIDER$$
##
##

from uuid import uuid4 as _uuid4
from uuid import UUID
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import ImmutableMultiDict
import pymysql, os, hashlib
from time import sleep
from flask import Flask, render_template_string, request, redirect, make_response, session, url_for
from jinja2 import Environment, Template, FileSystemLoader
from werkzeug.utils import secure_filename

def uuid4():
	return str(_uuid4())

def valid_uuid(uuid):
	try:
		UUID(uuid)
		return True
	except:
		return False

def sanitize(input):
    for i in blacklisted_chars:
        if i in str(input):
            input = input.replace(i,'')
    return input

def blacklist_checker(string):
        output = ""
        for i in blacklist:
                if i in string:
                        output += i+" "
        return output

def add_item_to_cart(productid):
    if not productid in session["cart_items"]:
        session["cart_items"] += productid
    return

def add_new_user(username, password):
	with connection.cursor() as cursor:
		uuid = uuid4()
		cursor.execute("INSERT INTO users(uuid, name, password) VALUES (%s, %s, %s);", (uuid, username, password))
		connection.commit()
	return uuid

def user_exists(username):
	with connection.cursor() as cursor:
		cursor.execute("SELECT * from users WHERE name=%s;", username)
		all = cursor.fetchall()
		if len(all) > 0:
			return True
		else:
			return False

def post_support_ticket(contact, message):
    with connection.cursor() as cursor:
        template = f"""Support request from: '{contact}'"""
        cursor.execute("INSERT INTO support(contact, message, timestamp) VALUES (%s,%s,NOW())", (render_template_string(template), message))
        connection.commit()
    return

def get_all_items():
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name, price, image_path FROM items;")
        all = cursor.fetchall()
    return all

def get_username(uuid):
	with connection.cursor() as cursor:
		cursor.execute("SELECT name FROM users WHERE uuid='%s'"% uuid)
		all = cursor.fetchall()
		return all[0]['name']

def get_uuid(username):
	with connection.cursor() as cursor:
		cursor.execute("SELECT uuid FROM users WHERE name=%s", username)
		all = cursor.fetchall()
		return all[0]['uuid']

def get_items_in_cart():
    ret_val = []
    for i in session["cart_items"]:
        with connection.cursor() as cursor:
                    cursor.execute("SELECT id, name, price, image_path FROM items WHERE id = " + str(i) + ";")
                    all = cursor.fetchall()
        ret_val += all
    return ret_val

def login(username, password):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT name, password, uuid FROM users WHERE name =%s;", username)
            user_pass = cursor.fetchall();
            if user_pass[0]['name'] == username and user_pass[0]['password'] == password:
                assign_cookie(user_pass[0]['uuid'])
                return True
            else:
                return False
    except Exception as e:
        print(e)
        return False

def login_uuid(username, password):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT name, password, uuid FROM users WHERE uuid=%s;", username)
            user_pass = cursor.fetchall();
            if user_pass[0]['uuid'] == username and user_pass[0]['password'] == password:
                assign_cookie(user_pass[0]['uuid'])
                return True
            else:
                return False
    except Exception as e:
        print(e)
        return False

def post_message(message, creator):
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM users WHERE name=%s;', creator)
            creator = cursor.fetchone()['id']
            cursor.execute('INSERT INTO messages(timestamp, message, creator) VALUES (NOW(), %s, %s);', (message, creator))
            connection.commit()
        return

def allowed_file(filename):
    if '.' in filename and filename.split('.',1)[1].lower() in ALLOWED_EXTENSIONS:
        return True
    else:
        return False


def get_product_details(id):
    with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM items WHERE id=%s;', id)
                output = cursor.fetchall()
                return output

def get_search_results(item_name):
    with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM items WHERE name LIKE %s;', "%" + item_name + "%")
                output = cursor.fetchall()
                return output

def assign_cookie(uuid):
    session['uuid'] = uuid

def get_total_items():
    with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) FROM items;')
                out = cursor.fetchall()[0]['COUNT(*)']
                return out

app = Flask(__name__, static_url_path='/static')
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["750 per day", "300 per hour"]
)

@app.route("/", methods=['POST', 'GET'])
@app.route("/index", methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=True)
def index():
    try:
        if not session["cart_items"]:
            session["cart_items"] = []
    except: 
        session["cart_items"] = []
    template = env.get_template('index.html')
    ret_items = get_all_items()
    if request.args.get('search'):
        ret_items = get_search_results(sanitize(request.args.get('search')))
    user = None
    if "uuid" in session:
        user = get_username(session['uuid'])
    rendered = template.render(items = ret_items, cart = len(session["cart_items"]), user=user)
    return(rendered)

@app.route("/register", methods=['POST','GET'])
@limiter.limit("1 per second", override_defaults=False)
def register():
        template = env.get_template('register.html')
        rendered = template.render()
        if request.method == 'POST':
            username = request.form.get('username')
            confirm_username = request.form.get('confirm_username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if username != confirm_username:
                return template.render(msg = "Usernames do not match")
            if password != confirm_password:
                return template.render(msg = "Passwords do not match")

            if len(username) > 10:
                return template.render(msg = "Username cannot be longer than 10 characters")

            uuid = add_new_user(username, password)
            return redirect("/login?uuid=" + uuid, code=302)
        else:
                pass
        return(rendered)

@app.route("/login", methods=['POST', 'GET'])
@limiter.limit("3/second", override_defaults=True)
def login_page():
    template = env.get_template('login.html')
    uuid = request.args['uuid'] if 'uuid' in request.args else ""
    rendered = template.render(uuid=uuid)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if login_uuid(username, password):
            return redirect("/main", code=302)
        else:
            rendered = template.render(msg = 'Unable to login.')
    else:
        pass
    return(rendered)

@app.route("/logout")
def logout():
	session.pop("uuid", None)
	return redirect("/", code=302)

@app.route("/user", methods=["GET"])
@limiter.limit("2/second", override_defaults=True)
def user_info():
	if not ("uuid" in session):
		return redirect("/login", code=302)
	if not valid_uuid(session['uuid']):
		return redirect("/login", code=302)
	template = open(env.get_template("user.html").filename).read()
	uuid = session['uuid']
	username = get_username(uuid)
	section = \
f"""
          <form action="#" class="ui form">
            <div class="field">
              <label>Username</label>
              <input type="text" name="username" readonly value="{username}" />
            </div>
            <div class="field">
              <label>UUID</label>
              <input type="text" name="uuid" readonly value="{uuid}" />
            </div>
          </form>
"""
	template = template.replace("FORMREPLACE", section)
	return render_template_string(template)

@app.route("/cart", methods=['POST', 'GET'])
@limiter.limit("2/second", override_defaults=True)
def cart_page():
    if not session["cart_items"]:
        return redirect("/",code=302)
    total = 0
    if request.args.get('remove') and request.args.get('remove').isdigit():
        in_cart = session["cart_items"]
        in_cart.remove(request.args.get('remove'))
        session["cart_items"] = in_cart
        if len(session["cart_items"]) > 0:
            return redirect('/cart', code=302)
        else:
            return redirect('/', code=302)
    template = env.get_template('cart.html')
    items = get_items_in_cart()
    for i in items:
        total += i['price']
    rendered = template.render(items = items, total = total, cart = len(session["cart_items"]))
    return rendered

@app.route("/view", methods=['GET', 'POST'])
@limiter.limit("1/second", override_defaults=True)
def message_board_page():
    check = ""; posts_from_database = []
    template = env.get_template('messages.html')
    try:
        if session["uuid"]:
            pass
        else:
            return redirect("/login", code=302)
    except: 
        return redirect("/login", code=302)
    try:
        if request.args.get('check') == 'messages':
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM messages;")
                posts_from_database = cursor.fetchall()
                check = 'messages'
        elif request.args.get('check') == 'support':
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM support;")
                posts_from_database = cursor.fetchall()
            check = 'support'
        else: 
            pass
    except:
        return template.render(check = 'support', posts = None, current_user = get_username(session["uuid"]))
    return template.render(check = check, posts = posts_from_database, current_user = get_username(session["uuid"]))

@app.route("/checkout", methods=['POST', 'GET'])
@limiter.limit("2/second", override_defaults=True)
def checkout_page():
    total = 0
    if not session["cart_items"]:
        return redirect("/",code=302)
    template = env.get_template('checkout.html')
    items = get_items_in_cart()
    for i in items:
        total += i['price']
    return template.render(total = total)

@app.route("/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal", methods=['POST', 'GET'])
@limiter.limit("2 per second", override_defaults=True)
def support_page():
    template = env.get_template('support.html')
    message = "Welcome to the support portal!"
    if request.form.get('contact') and request.form.get('message'):
        if "{{" in request.form.get('contact') or "}}" in request.form.get('contact'):
            return template.render(message = "Why would you need '{{' or '}}' in a contact value?")
        else:
            output = blacklist_checker(request.form.get('contact').lower())
            if len(output) > 0:
                return template.render(message = "Hmmm, you seem to have hit a our WAF with the following chars: " + str(output))
            else:
                post_support_ticket(request.form.get('contact'), request.form.get('message'))
                message = "Ticket has been posted!"
    elif request.form.get('contact') and not request.form.get('message'):
        message = "Please include a message!"
    elif not request.form.get('contact') and request.form.get('message'):
        message = "Please include a contact method!"
    else:
        pass
    return template.render(message = message)

@app.route("/main", methods=['POST', 'GET'])
@limiter.limit("99/second", override_defaults=True)
def main_menu_page():
    template = env.get_template('main.html')
    admin_uuid = get_uuid("chiv")
    try:
        if session["uuid"] and (admin_uuid == session['uuid']):
            pass
        elif admin_uuid != session['uuid']:
            return redirect('/', code=302)
        else:
            return redirect("/login", code=302)
    except:
        return redirect('/login', code=302)
    if request.method == "POST":
        if request.form.get('message'):
            post_message(sanitize(request.form.get('message')), get_username(session["uuid"]))
    else:
        pass
    return template.render(user = get_username(session["uuid"]))

@app.route("/product-details")
@app.route("/product-details/")
def redirprod():
    return redirect("/product-details/1", code=302)

@app.route("/product-details/<productid>", methods=['GET','POST'])
@limiter.limit("1/second", override_defaults=True)
def product_details(productid):
    template = env.get_template('product-details.html')
    total = int(get_total_items())
    try:
        if productid.isdigit() and int(productid) > total or int(productid) < 1:
                    template = env.get_template('invalid.html')
                    print ("Invalid product ID")
                    rendered = template.render(issue = 'Invalid product ID')
                    return rendered
    except:
        pass
    try:
        if request.form.get('new_item'):
            add_item_to_cart(sanitize(request.form.get('new_item')))
    except:
        print ("Passed in product new item")
        pass
    details = get_product_details(productid)
    if len(details) == 0:
        template = env.get_template('invalid.html')
        print ("Invalid product ID")
        rendered = template.render(issue = 'Invalid product ID')
        return rendered
    name = details[0]['name']
    price = str(details[0]['price'])
    image_path = str(details[0]['image_path'])
    description = str(details[0]['description'])
    rendered = template.render(description = description, price = price, cart = len(session["cart_items"]), name = name, image_path = image_path, product_id = productid)
    return rendered

#if __name__ == "__main__":
blacklist = ["_", "'", ".", "for", "set", "if", "macro", "call", "filter", "assignments", "block", "extends", "blocks", "else"]
blacklisted_chars = "'_{}%<>/\"?"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
env = Environment(loader=FileSystemLoader('templates'))
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'SUPxxxxxxXXXXXxxxxxXxxXXxxxxxxxx'
while True:
	try:
		connection = pymysql.connect(host='localhost',
        		                 user='chivato',
                		         password='xXXXxxxxxXXXXXXxxxxx',
                        		 db='shop',
	                        	 charset='utf8mb4',
	        	                 cursorclass=pymysql.cursors.DictCursor)
		break
	except:
		sleep(1)
if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=1337)
    
#####################################################
##
##
    
