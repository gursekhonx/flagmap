from flask import Flask, request
app = Flask(__name__)

@app.route("/search")
def search():
    name = request.args.get("name")
    cur.execute("SELECT * FROM items WHERE name = %s", (name,))
    return "ok"
