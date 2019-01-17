from flask import Flask
app=Flask(__name__)

@app.route("/")
def index():
    return "Web App"

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0:8900')
