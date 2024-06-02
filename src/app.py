from flask import Flask, render_template, request, redirect, url_for, flash # type: ignore
from flask_login import LoginManager, login_user, current_user, logout_user # type: ignore
from werkzeug.security import check_password_hash, generate_password_hash # type: ignore
from models import User, db

from werkzeug import exceptions # type: ignore

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret-key-goes-here'
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already taken')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/profile')
def profile():
    if current_user.is_authenticated:
        return render_template('profile.html', user=current_user)
    else:
        return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('indexx.html')
    
@app.route('/ОстаткиПластика')
def plast():
    return render_template('пластик.html')

@app.route('/ИзменениеКлимата')
def klim():
    return render_template('климат.html')

@app.route('/ЗагрязнениеВоды')
def water():
    return render_template('вода.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.errorhandler(400)
def page_not_found(e):
    return render_template('400.html'), 400

@app.errorhandler(401)
def page_not_found(e):
    return render_template('401.html'), 401


@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(405)
def page_not_found(e):
    return render_template('405.html'), 405

@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500

@app.errorhandler(501)
def page_not_found(e):
    return render_template('501.html'), 501

@app.errorhandler(502)
def page_not_found(e):
    return render_template('502.html'), 502

@app.errorhandler(503)
def page_not_found(e):
    return render_template('503.html'), 503

class Except402 (exceptions.HTTPException):
    code = 402
    description = 'Что то 402!'

def handle_402(e):
    return render_template('402.html')

app.register_error_handler(Except402, handle_402)

@app.route('/400')
def er400():
    return render_template('400.html')

@app.route('/401')
def er401():
    return render_template('401.html')

@app.route('/402')
def er402():
    return render_template('402.html')

@app.route('/403')
def er403():
    return render_template('403.html')

@app.route('/404')
def er404():
    return render_template('404.html')

@app.route('/405')
def er405():
    return render_template('405.html')

@app.route('/500')
def er500():
    return render_template('500.html')

@app.route('/501')
def er501():
    return render_template('501.html')

@app.route('/502')
def er502():
    return render_template('502.html')

@app.route('/503')
def er503():
    return render_template('503.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", debug=True)