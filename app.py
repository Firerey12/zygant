from flask import Flask, render_template

app = Flask(
    __name__,
    template_folder='./templates',
    static_folder='./templates/static'
)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/assets')
def assets():
    return render_template('index.html')  # placeholder until Week 4

@app.route('/scan')
def scan():
    return render_template('index.html')  # placeholder until Week 4

@app.route('/cve')
def cve():
    return render_template('index.html')  # placeholder until Week 5

@app.route('/users')
def users():
    return render_template('index.html')  # placeholder until Week 5

@app.route('/audit')
def audit():
    return render_template('index.html')  # placeholder until Week 5

@app.route('/reports')
def reports():
    return render_template('index.html')  # placeholder until Week 6

@app.route('/support')
def support():
    return render_template('index.html')  # placeholder until Week 6

if __name__ == '__main__':
    app.run(debug=True)
