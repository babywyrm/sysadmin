from flask import Flask, jsonify, abort, make_response, url_for
from flask import request
from socket import *
from flask_httpauth import HTTPBasicAuth

sock = socket(AF_INET, SOCK_STREAM)
sock.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)
sock.bind(('0.0.0.0',0))

app = Flask(__name__)
auth = HTTPBasicAuth()

# [ list, ( tuple
tasks = [
    {
        'id':1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol',
        'done': False
    },
    {
        'id': 2,
        'title': u':Learn python',
        'description': u'Need to find good tutorial on web',
        'done': False
    }
]


invalid_Task_JSON_404 = {'error': 'Invalid Task Id'}
invalid_Task_JSON_400 = {'error': 'Bad Request'}

@auth.get_password
def get_password(username):
    if(username == 'uday'):
        return 'python'

    return None


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'Response':'Invalid credentials'}), 401) #403 to prevent dialog box

@app.route('/todo/api/v1.0/tasks', methods=['GET'])
@auth.login_required
def get_Tasks():
    return jsonify({'tasks': [make_public_task(task) for task in tasks]})

@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['GET'])
def get_Task(task_id):

    if(len(str(task_id)) == 0):
        abort(400)

    task = [task for task in tasks if task['id'] == task_id]
    if(len(task) == 0):
        abort(404)

    return jsonify({'task': task})

@app.route('/todo/api/v1.0/tasks', methods=['POST'])
def create_Task():
     if not request.json or not 'title' in request.json:
      abort(400)

     task = {
         'id': tasks[-1]['id'] + 1,
         'title': request.json['title'],
         'description': request.json.get('description',""),
         'done': False
     }
     tasks.append(task)

     return jsonify({'tasks': tasks})


@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
def update_Task(task_id):
    task = [task for task in tasks if task['id'] == task_id]

    if(len(task) == 0):
        abort(404)

    if(not request.json):
        abort(400)

    if('title' in request.json and type(request.json['title']) is not str):
        abort(400)

    if('description' in request.json and type(request.json['description']) is not str):
        abort(400)

    if ('done' in request.json and type(request.json['done']) is not bool):
        abort(400)

    task[0]['title'] = request.json.get('title', tasks[0]['title'])
    task[0]['description'] = request.json.get('description',tasks[0]['description'])
    task[0]['done'] = request.json.get('done', tasks[0]['done'])
    print("Tasks ended")
    return make_response(jsonify({"Response":"Updated"}), 200)

@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['DELETE'])
def delete_Task(task_id):
    task = [task for task in tasks if task['id'] == task_id]

    if(len(task) == 0):
        abort(404)

    print("What is task", task[0])
    tasks.remove(task[0])

    return make_response(jsonify({"Response":"Deleted successfully"}), 200)


def make_public_task(task):
    newtask = {}
    for field in task:
        if(field == 'id'):
            newtask['uri'] = url_for('get_Task', task_id = task['id'], _external=True)
        else:
            newtask[field] = task[field]

    return newtask


@app.route('/')
def index():
    return 'Copy and Paste in browser: /todo/api/v1.0/tasks'

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify(invalid_Task_JSON_404), 404)

@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify(invalid_Task_JSON_400), 400)

app.run('0.0.0.0',5000)

##
##
