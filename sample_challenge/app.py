from flask import Flask, request, render_template_string
import pickle
import os
import subprocess

app = Flask(__name__)


@app.route("/search")
def search():
    name = request.args.get("name")
    cur.execute(f"SELECT * FROM items WHERE name = '{name}'")
    return "ok"


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    template = "Hello " + name + "!"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "pinged"


@app.route("/load")
def load():
    data = request.args.get("data")
    obj = pickle.loads(data.encode())
    return str(obj)


@app.route("/file")
def file():
    fname = request.args.get("f")
    return open(os.path.join("uploads", request.args.get("f"))).read()
