Welcome from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path=&#39;&#39;,static_folder=&#39;static&#39;,template_folder=&#39;templates&#39;)

#Define connection for database
def connections():
    try:
        connector = mysql.connector.connect(user=&#39;admin&#39;, password=&#39;ToughPasswordToCrack&#39;, host=&#39;127.0.0.1&#39;, database=&#39;writer&#39;)
        return connector
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return (&#34;Something is wrong with your db user name or password!&#34;)
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            return (&#34;Database does not exist&#34;)
        else:
            return (&#34;Another exception, returning!&#34;)
    else:
        print (&#39;Connection to DB is ready!&#39;)

#Define homepage
@app.route(&#39;/&#39;)
def home_page():
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
    cursor = connector.cursor()
    sql_command = &#34;SELECT * FROM stories;&#34;
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template(&#39;blog/blog.html&#39;, results=results)

#Define about page
@app.route(&#39;/about&#39;)
def about():
    return render_template(&#39;blog/about.html&#39;)

#Define contact page
@app.route(&#39;/contact&#39;)
def contact():
    return render_template(&#39;blog/contact.html&#39;)

#Define blog posts
@app.route(&#39;/blog/post/&lt;id&gt;&#39;, methods=[&#39;GET&#39;])
def blog_post(id):
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
    cursor = connector.cursor()
    cursor.execute(&#34;SELECT * FROM stories WHERE id = %(id)s;&#34;, {&#39;id&#39;: id})
    results = cursor.fetchall()
    sql_command = &#34;SELECT * FROM stories;&#34;
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template(&#39;blog/blog-single.html&#39;, results=results, stories=stories)

#Define dashboard for authenticated users
@app.route(&#39;/dashboard&#39;)
def dashboard():
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    return render_template(&#39;dashboard.html&#39;)

#Define stories page for dashboard and edit/delete pages
@app.route(&#39;/dashboard/stories&#39;)
def stories():
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
    cursor = connector.cursor()
    sql_command = &#34;Select * From stories;&#34;
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template(&#39;stories.html&#39;, results=results)

@app.route(&#39;/dashboard/stories/add&#39;, methods=[&#39;GET&#39;, &#39;POST&#39;])
def add_story():
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
    if request.method == &#34;POST&#34;:
        if request.files[&#39;image&#39;]:
            image = request.files[&#39;image&#39;]
            if &#34;.jpg&#34; in image.filename:
                path = os.path.join(&#39;/var/www/writer.htb/writer/static/img/&#39;, image.filename)
                image.save(path)
                image = &#34;/img/{}&#34;.format(image.filename)
            else:
                error = &#34;File extensions must be in .jpg!&#34;
                return render_template(&#39;add.html&#39;, error=error)

        if request.form.get(&#39;image_url&#39;):
            image_url = request.form.get(&#39;image_url&#39;)
            if &#34;.jpg&#34; in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system(&#34;mv {} {}.jpg&#34;.format(local_filename, local_filename))
                    image = &#34;{}.jpg&#34;.format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace(&#39;/tmp/&#39;,&#39;&#39;)
                        os.system(&#34;mv /tmp/{} /var/www/writer.htb/writer/static/img/{}&#34;.format(image, image))
                        image = &#34;/img/{}&#34;.format(image)
                    except PIL.UnidentifiedImageError:
                        os.system(&#34;rm {}&#34;.format(image))
                        error = &#34;Not a valid image file!&#34;
                        return render_template(&#39;add.html&#39;, error=error)
                except:
                    error = &#34;Issue uploading picture&#34;
                    return render_template(&#39;add.html&#39;, error=error)
            else:
                error = &#34;File extensions must be in .jpg!&#34;
                return render_template(&#39;add.html&#39;, error=error)
        author = request.form.get(&#39;author&#39;)
        title = request.form.get(&#39;title&#39;)
        tagline = request.form.get(&#39;tagline&#39;)
        content = request.form.get(&#39;content&#39;)
        cursor = connector.cursor()
        cursor.execute(&#34;INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,&#39;Published&#39;,now(),%(image)s);&#34;, {&#39;author&#39;:author,&#39;title&#39;: title,&#39;tagline&#39;: tagline,&#39;content&#39;: content, &#39;image&#39;:image })
        result = connector.commit()
        return redirect(&#39;/dashboard/stories&#39;)
    else:
        return render_template(&#39;add.html&#39;)

@app.route(&#39;/dashboard/stories/edit/&lt;id&gt;&#39;, methods=[&#39;GET&#39;, &#39;POST&#39;])
def edit_story(id):
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
    if request.method == &#34;POST&#34;:
        cursor = connector.cursor()
        cursor.execute(&#34;SELECT * FROM stories where id = %(id)s;&#34;, {&#39;id&#39;: id})
        results = cursor.fetchall()
        if request.files[&#39;image&#39;]:
            image = request.files[&#39;image&#39;]
            if &#34;.jpg&#34; in image.filename:
                path = os.path.join(&#39;/var/www/writer.htb/writer/static/img/&#39;, image.filename)
                image.save(path)
                image = &#34;/img/{}&#34;.format(image.filename)
                cursor = connector.cursor()
                cursor.execute(&#34;UPDATE stories SET image = %(image)s WHERE id = %(id)s&#34;, {&#39;image&#39;:image, &#39;id&#39;:id})
                result = connector.commit()
            else:
                error = &#34;File extensions must be in .jpg!&#34;
                return render_template(&#39;edit.html&#39;, error=error, results=results, id=id)
        if request.form.get(&#39;image_url&#39;):
            image_url = request.form.get(&#39;image_url&#39;)
            if &#34;.jpg&#34; in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system(&#34;mv {} {}.jpg&#34;.format(local_filename, local_filename))
                    image = &#34;{}.jpg&#34;.format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace(&#39;/tmp/&#39;,&#39;&#39;)
                        os.system(&#34;mv /tmp/{} /var/www/writer.htb/writer/static/img/{}&#34;.format(image, image))
                        image = &#34;/img/{}&#34;.format(image)
                        cursor = connector.cursor()
                        cursor.execute(&#34;UPDATE stories SET image = %(image)s WHERE id = %(id)s&#34;, {&#39;image&#39;:image, &#39;id&#39;:id})
                        result = connector.commit()

                    except PIL.UnidentifiedImageError:
                        os.system(&#34;rm {}&#34;.format(image))
                        error = &#34;Not a valid image file!&#34;
                        return render_template(&#39;edit.html&#39;, error=error, results=results, id=id)
                except:
                    error = &#34;Issue uploading picture&#34;
                    return render_template(&#39;edit.html&#39;, error=error, results=results, id=id)
            else:
                error = &#34;File extensions must be in .jpg!&#34;
                return render_template(&#39;edit.html&#39;, error=error, results=results, id=id)
        title = request.form.get(&#39;title&#39;)
        tagline = request.form.get(&#39;tagline&#39;)
        content = request.form.get(&#39;content&#39;)
        cursor = connector.cursor()
        cursor.execute(&#34;UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s&#34;, {&#39;title&#39;:title, &#39;tagline&#39;:tagline, &#39;content&#39;:content, &#39;id&#39;: id})
        result = connector.commit()
        return redirect(&#39;/dashboard/stories&#39;)

    else:
        cursor = connector.cursor()
        cursor.execute(&#34;SELECT * FROM stories where id = %(id)s;&#34;, {&#39;id&#39;: id})
        results = cursor.fetchall()
        return render_template(&#39;edit.html&#39;, results=results, id=id)

@app.route(&#39;/dashboard/stories/delete/&lt;id&gt;&#39;, methods=[&#39;GET&#39;, &#39;POST&#39;])
def delete_story(id):
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
    if request.method == &#34;POST&#34;:
        cursor = connector.cursor()
        cursor.execute(&#34;DELETE FROM stories WHERE id = %(id)s;&#34;, {&#39;id&#39;: id})
        result = connector.commit()
        return redirect(&#39;/dashboard/stories&#39;)
    else:
        cursor = connector.cursor()
        cursor.execute(&#34;SELECT * FROM stories where id = %(id)s;&#34;, {&#39;id&#39;: id})
        results = cursor.fetchall()
        return render_template(&#39;delete.html&#39;, results=results, id=id)

#Define user page for dashboard
@app.route(&#39;/dashboard/users&#39;)
def users():
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return &#34;Database Error&#34;
    cursor = connector.cursor()
    sql_command = &#34;SELECT * FROM users;&#34;
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template(&#39;users.html&#39;, results=results)

#Define settings page
@app.route(&#39;/dashboard/settings&#39;, methods=[&#39;GET&#39;])
def settings():
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return &#34;Database Error!&#34;
    cursor = connector.cursor()
    sql_command = &#34;SELECT * FROM site WHERE id = 1&#34;
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template(&#39;settings.html&#39;, results=results)

#Define authentication mechanism
@app.route(&#39;/administrative&#39;, methods=[&#39;POST&#39;, &#39;GET&#39;])
def login_page():
    if (&#39;user&#39; in session):
        return redirect(&#39;/dashboard&#39;)
    if request.method == &#34;POST&#34;:
        username = request.form.get(&#39;uname&#39;)
        password = request.form.get(&#39;password&#39;)
        password = hashlib.md5(password.encode(&#39;utf-8&#39;)).hexdigest()
        try:
            connector = connections()
        except mysql.connector.Error as err:
            return (&#34;Database error&#34;)
        try:
            cursor = connector.cursor()
            sql_command = &#34;Select * From users Where username = &#39;%s&#39; And password = &#39;%s&#39;&#34; % (username, password)
            cursor.execute(sql_command)
            results = cursor.fetchall()
            for result in results:
                print(&#34;Got result&#34;)
            if result and len(result) != 0:
                session[&#39;user&#39;] = username
                return render_template(&#39;success.html&#39;, results=results)
            else:
                error = &#34;Incorrect credentials supplied&#34;
                return render_template(&#39;login.html&#39;, error=error)
        except:
            error = &#34;Incorrect credentials supplied&#34;
            return render_template(&#39;login.html&#39;, error=error)
    else:
        return render_template(&#39;login.html&#39;)

@app.route(&#34;/logout&#34;)
def logout():
    if not (&#39;user&#39; in session):
        return redirect(&#39;/&#39;)
    session.pop(&#39;user&#39;)
    return redirect(&#39;/&#39;)

if __name__ == &#39;__main__&#39;:
   app.run(&#34;0.0.0.0&#34;)
