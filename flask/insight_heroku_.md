# Building an Insight project with Python, Flask, and Heroku

A common goal in Insight data science projects is to deploy one's work as an app. The recommended app is Flask due to its dynamic page construction and easy interoperability with SQL databases. Heroku is then a great choice for deployment as it interacts easily with Python and Flask.

However a lot of information is out-of-date or suboptimal. This project will document how I built my Insight project app using Python, Flask, and Heroku. 

*This project is adapted from and enormously indebted to the excellent "Flask by Example" tutorial found [here](https://realpython.com/flask-by-example-part-1-project-setup/). Basically I take this tutorial a little less far, fix some errors and adapt it to the requirements of the Insight project.

## Contents

I will document how I:

1. Built local, and web (production) versions of the app using conda, Python and Heroku.

\[More ambitious sections of original TOC redacted \]

2. Did all this using the latest software and environments available in Ubuntu 18.04 LTS.

### Hacking together conda and pip: a note

One approach I took (that is arguably a bit controversial) was to keep the project in Conda on the Ubuntu side. I find Conda the superior scientific programming environment as do many. However Heroku runs on pip, and further, does not always keep up with package versions in conda-forge. The way to make the two compatible is not too complicated: the Conda variables need to be exported to requirements_conda.txt, and the syntax of the requirements needs to be slightly "hacked" and saved in a pip-compatible "requirements.txt" file. I will specify what to do but be ready for that. I found it well worth the trouble to keep my Conda, and I would advise it presently as *psycopg2* is broken in Ubuntu 18.04 when installed with *pip*, but not *conda*, and *psycopg2* is needed for *SQLAlchemy*. However YMMV.

## Chapter 1: Setting up the application folder and repositories

1. Make a folder and enter it:
    ````
    cd $CODE # I will use this env var to denote the base directory
    mkdir insight_app
    cd insight_app
    ````
2. Set up a repository on github or gitlab. Choose to initialize with a README. Then link this folder to the repo:
    ````
    git init
    git remote add origin https://github.com/yourname/insight_app
    git pull origin master
    git config credential.helper store
    ````
    (all instances of *yourname* in this tutorial should be replaced with your username, handle, or whatever)
3. Set up and activate your conda environment, and install flask and gunicorn packages:
    ````
    conda create -y -n insight_app
    source activate insight_app
    conda install -c conda-forge flask gunicorn
    ````
4. *Your first Conda -> Pip hack*. Conda has a more sophisticated package management approach than Pip, and Heroku sometimes chokes on the new package versions available at conda-forge. To convert a conda requirements export to a pip export, two things need to be done:

    1. Export the conda package requirements:
        ````
        conda list --export > requirements_new.txt
        ````
    2. Keep *only* the principal packages that you are installing. For example, in the present case (at least at time of publication of this gist) your conda export will read as follows:
        ````
        # This file may be used to create an environment using:
        # $ conda create --name <env> --file <this file>
        # platform: linux-64
        ca-certificates=2018.4.16=0
        certifi=2018.4.16=py36_0
        click=6.7=py_1
        flask=1.0.2=py_1
        gunicorn=19.8.1=py36_0
        itsdangerous=0.24=py_2
        jinja2=2.10=py36_0
        libgcc-ng=7.2.0=hdf63c60_3
        markupsafe=1.0=py36_0
        ncurses=5.9=10
        openssl=1.0.2o=0
        pip=9.0.3=py36_0
        python=3.6.5=1
        readline=7.0=0
        setuptools=39.2.0=py36_0
        sqlite=3.20.1=2
        tk=8.6.7=0
        werkzeug=0.14.1=py_0
        wheel=0.31.0=py36_0
        xz=5.2.3=0
        ````
    reduce this to:
        ````
        flask=1.0.2=py_1
        gunicorn=19.8.1=py36_0
        ````
    2. change the *first* equals sign on each line ("=") to a double equals ("==") and delete everything on the line starting from the second equals sign. So the previous file now changes to:
        ````
        flask==1.0.2
        gunicorn==19.8.1
        ````
    3. use the filename *requirements_conda.txt* as a dummy file and when it has been hacked copy to *requirements.txt*, which is what Heroku will read:
        ````
        cp requirements_conda.txt requirements_txt
        ````
        And that's it. Further conda hacks will proceed in this fashion.
        
5. Set up your heroku repositories

*Prerequisite*: Download and install the [Heroku toolbelt](https://toolbelt.heroku.com). The setup will include signing up f or a free (known as the devel-hobby level) Heroku account and provide you with login credentials. Enter

    heroku login
    
and your credentials to log into your Heroku account.

Heroku has a great many capabilities but here we will keep it very simple. (If you want to learn more their article about the [process model](https://devcenter.heroku.com/articles/process-model) which gives rise to this Procfile is very good). First, create a file named exactly *Procfile* (no extension) containing the line:

    web: gunicorn app:app

this will lock you into using the filename *app.py* for your app, but this is quite common for Flask. Finally we need another small file to tell Heroku which Python runtime to use. At the time of publication, 3.6.5 was the latest python. Create a file *runtime.txt* containing the line:

    python-3.6.5

Now we are ready to set up the Heroku repository:

    heroku create insight-app-yourname

(Note that if you want to delete and start over with your Heroku apps, use for example:

        heroku apps::destroy insight-app-yourname
        
)
Heroku lets you have up to five projects for free.
Set up git repositories on your new Heroku projects:

    git remote add web git@heroku.com:insight-app-yourname.git

With the creation of our *requirements.txt* and *runtime.txt* files, we have enough to make our first push to our local and Heroku repositories:

    git add .
    git commit -a -m "repository setup"
    git push origin master
    git push web master

Hopefully you can start to see the convenience of this approach: the same git commit can be pushed to local and/or web repositories as desired.
 Fl
## Chapter 2: "Hello world" app

Create the following file as *app.py*:

    from flask import Flask
    app = Flask(__name__)
    @app.route('/')
    def hello():
        return "Insight web app created by yourname."

    if __name__ == '__main__':
        app.run()

Briefly, the decorator function *@app.route* is establishing how to handle visits to the domain name ('/'). Here a hello world-type message is produced. Test locally first by running:

    python app.py
    
Your terminal should display:

    * Serving Flask app "app" (lazy loading)
    * Environment: production
    WARNING: Do not use the development server in a production environment.
    Use a production WSGI server instead.
    * Debug mode: off
    * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
    
Showing that it is listening. Go to either the above address or its alias, http://localhost:5000/ , and you should see the contents of your app:

    Insight web app created by yourname.
    
The magic of Heroku is that by following the above procedures, the very same site is already live on the web. Go to:

    https://insight-app-yourname.herokuapp.com/
    
you should see the same result message. Your app is already deployed to the web.

## Chapter 2: Set up a form and response

Here we set up interactivity on our page through an interaction between Flask and HTML. This demo app will accept a word as input, then print out an ordered list of letters for that word.

We will need Python's *requests* library, so let's add it to Conda and our *requirements.txt* file:

    conda install -c conda-forge requests
    conda list --export > requirements_new.txt
    
now add *only* the new line for requests (in my case it was *requests=2.19.1=py36_0*) into the *requirements.txt* file (in my case as *requests==2.19.1*).

Commit your changes and push to the origin and web repositories; make sure Heroku handles the new requirement okay.

Make a new folder called *templates*, and inside it create an *index.html* file:

    <!DOCTYPE html>
    <html>
      <head>
        <title>Yourname Insight App</title>
      </head>
      <body>
        <div class="container">
          <h1>Yourname Insight Application</h1>
          <form role="form" method='POST' action='/'>
            <div class="form-group">
              <input type="text" name="word" placeholder="Enter word" style="max-width: 300px;" autofocus required>
            </div>
            <button type="submit">Submit</button>
          </form>
          <br>
        </div>
      </body>
    </html>

If you haven't looked at an HTML page much before:
- It has a *head* and a *body*.
- The *head* passes information to the browser, and often scripts are run there.
- The *body* contains the visible page content. Content is usually positioned using *div* tags. Here we also have a *form* tag containing an *input* and a *button* that submits the input.

We now need to alter *app.py* so that the decorator function points to this HTML page. Open *app.py* for editing. Add some imports by changing your imports to:

    from flask import Flask, render_template, request
    
and change the decorator call to:

    @app.route('/', methods=['GET', 'POST'])
    def index():
        errors = []
        trends = ''
        if request.method == "POST":
            # get url that the user has entered
            try:
                word = request.form['word']
                # print statements just print to terminal
                print("word was:")
                print(word)
            except:
                print("error")
        return render_template('index.html')

The app now adds some dynamic behavior on the root page. In particular, if it receives a POST request, it acquires the contents of the form, prints the content of the form to your terminal window, then re-renders the page.

Test the app locally by running *python app.py* and directing your browser again to localhost:5000 . You should see the HTMl page you created with a form for a word. When you enter the word, it should appear in your browser window.

Push the changes to your origin and web repositories, and navigate to your web page. You will see the exact same app live on the web. Here, you will not see the printouts to terminal window.

## Chapter 3: Add dynamic content

Now we introduce some text processing and error handling. Obviously the text processing could incorporate all the algorithms you have already developed for your Insight project, so after this chapter you may have all the hacking skills you need to get your Insight project live on the web. Later chapters will add the algorithms specific to my project to give an example of something more complex. It will also make use of database migration through Alembic, to take advantage of easy use of Postgres through Heroku.

Let's first create a short file containing the processing algorithm. Here, we separate a word into its letters. Create a new file called *get_letters.py*:

    def get_letters(word):
        letters = list(word)
        return letters

Now we expand the functionality of *app.py* to call this method with the contents of the POST query, process the data using the *get_letters()* function, return the output, and handle errors in an effective way. Import this new script:

    from get_letters import get_letters

Change the route one more time to:

    @app.route('/', methods=['GET', 'POST'])
    def index():
        errors = []
        letters = []
        if request.method == "POST":
            # get url that the user has entered
            try:
                word = request.form['word']
                letters = get_letters(word)
            except:
                errors.append(
                    "Unable to get URL. Please make sure it's valid and try again."
                )
        return render_template('index.html', letters=letters, errors=errors)

Here we add some *jinja2* code (in curly braces) to the HTML page to make it dynamic and incorporate the passed arguments of letters and errors. Alter the *body* of the HTMl page as follows:

    <body>
        <div class="container">
          <h1>Yourname Insight App</h1>
          <form role="form" method='POST' action='/'>
            <div class="form-group">
              <input type="text" name="word" placeholder="Enter word" style="max-width: 300px;" autofocus required>
            </div>
            <button type="submit">Submit</button>
          </form>
          <br>
          {% for error in errors %}
            <h4>{{ error }}</h4>
          {% endfor %}
        </div>
        <div>
            {% if letters %}
                <h2>Letters Of Your Word</h2>
                <br>
                <div id="results">
                    <ol>
                    {% for letter in letters %}
                        <li>{{ letter }}</li>
                    {% endfor %}
                  </table>
                </div>
            {% endif %}
        </div>
    </body>

At this point there is not much use for the error handling, but it will become important later.

Test this functionality by running *app.py* and visiting localhost:5000 . After entering a word, you should see its letters in the form of a numbered list.

Once you are happy with this, commit your changes, for example:

    git add .
    git commit -a -m "added jinja2 functionality"
    git push origin master; git push web master
    
And you will see the exact same functionality on your web site.

Hopefully you can see that this makes getting up and running with your algorithms on the web quite easy: test to localhost, push, and you're all done -- Heroku takes care of the rest.

