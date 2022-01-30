#!/usr/bin/python3.8

############# c/o chiv/jack 
############# hackthebox.com/$SPIDER$
###########################################
##
##

from flask import Flask, session, flash, redirect, request, render_template
from lxml import etree
from base64 import b64decode, b64encode

basexml = """<!-- API Version {0} -->
<root>
    <data>
        <username>{1}</username>
        <is_admin>0</is_admin>
    </data>
</root>"""

app = Flask(__name__)
app.config['SECRET_KEY'] = '\xc5n\xfc\xecz?\x91\xecS\x88E)\x9d\x06\x85\xe1\xbfL\xce\xc5\xa1\x9c\xbaD\xbb6B\x98J' \
                           '\xc1<\x15\xf5(\xd9u\xb0\xbf\xfd,p\x17\xd2\xef$;\xb6\xb8,' \
                           '-\xd2\xf8\xad\x86k\x97_\xa4J\x81\xf4\x8c\xc0 '

blacklisted_chars = "_{}%<>/\"?"


def create_xml(version, username):
    return b64encode(basexml.format(version, username).encode())


def sanitize(inp):
    for i in blacklisted_chars:
        if i in str(inp):
            inp = inp.replace(i, '')
    return inp

def get_username():
    parsed_xml = None
    xml = b64decode(session['lxml']).decode()
    parser = etree.XMLParser(no_network=False, dtd_validation=False)
    try:
        print(xml)
        doc = etree.fromstring(str(xml), parser)
        print("doc")
        parsed_xml = etree.tostring(doc)
        return (doc[0][0].text)
    except Exception as e:
        print(e)
        pass
    return "ERROR"


@app.route("/logout")
def logout():
    session.pop('lxml')
    return redirect("/login", code=302)

@app.route("/login", methods=["GET", "POST"])
def login():
    if "lxml" in session:
        return redirect("/site", code=302)
    if request.method == "POST":
        if request.form['username']:
            username = sanitize(request.form.get("username", 0))
            if len(username) > 0:
                if request.form['version']:
                    session["lxml"] = create_xml(request.form['version'], request.form.get("username"))
                else:
                    session["lxml"] = create_xml("1.0.0", request.form.get("username"))
                session['points'] = 0
                return redirect("/site", code=302)
    return render_template("login.html")


@app.route("/site", methods=["GET", "POST"])
def site():
    if not session['lxml']:
        return redirect("/login", code=302)
    elif request.method == "POST":
        if request.form["points"]:
            session['points'] = int(request.form["points"])
    return render_template("game.html", points=session["points"], username=get_username())


@app.route('/')
def main():
	return redirect("/login", code=302)

if __name__ == '__main__':
    app.run()

###########################################
##
##
