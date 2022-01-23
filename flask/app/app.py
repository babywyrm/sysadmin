#######
####### starting over from- actually- nowhere
#######

from flask import Flask
app = Flask(__name__)

@app.route("/")
def this():
    return "Leave me be, ty and god bless, from Flask"

if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, port=80)

####################
##
##
