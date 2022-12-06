import flask_login
from flask import Flask, render_template, request, redirect, flash, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
import pdfkit

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = '' # тут secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:@localhost/site' # здесь после postgres , перед @ пароль
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["CLIENT_PDF"] = "E:/AudiotoText/Flask_File_Downloads/filedownload/files/pdf"

db = SQLAlchemy(app)
manager = LoginManager(app)

app_context = app.app_context()
app_context.push()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(1024), nullable=False, unique=True)
    password = db.Column(db.String(1024), nullable=False)
    name = db.Column(db.String(1024), nullable=False)
    age = db.Column(db.String(1024), nullable=False)
    country = db.Column(db.String(1024), nullable=False)
    town = db.Column(db.String(1024), nullable=False)
    email = db.Column(db.String(1024), nullable=False)
    phone = db.Column(db.String(1024), nullable=False)
    profession = db.Column(db.String(1024), nullable=False)
    interests = db.Column(db.String(1024), nullable=False)
    skills = db.Column(db.String(1024), nullable=False)
    education = db.Column(db.String(1024), nullable=False)
    experience = db.Column(db.String(1024), nullable=False)
    extracurriculars = db.Column(db.String(1024), nullable=False)
    languages = db.Column(db.String(1024), nullable=False)
    image_url = db.Column(db.String(1024), nullable=False)


db.create_all()


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/', methods=['GET'])
def default():
    return render_template('default.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    login = request.args.get('user_name')
    password = request.args.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('form'))
        else:
            flash('Your password or login are not correct')
    else:
        flash('You do not fill all the gaps')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.args.get('user_name_reg')
    password = request.args.get('password_reg')
    password2 = request.args.get('password_reg_2')

    if not login:
        flash('You do not fill the login')
    elif not password:
        flash('You do not fill the password')
    elif not password2:
        flash('You do not fill the retype password')
    elif not (login or password or password2):
        flash('You do not fill all the gaps')
    elif login and password and password2 and password != password2:
        flash('Passwords are not equal')
    elif login and password and password2 and password == password2:
        if User.query.filter_by(login=login).first() is None:
            new_user = generate_user(login, password)
            db.session.add(new_user)
            db.session.commit()
            return render_template('login.html')
        else:
            flash('Your login is not unique')

    return render_template('register.html')


def generate_user(login_reg, password_reg):
    hash = generate_password_hash(password_reg)
    user = User(login=login_reg, password=hash)
    user.name = ''
    user.age = ''
    user.country = ''
    user.town = ''
    user.email = ''
    user.phone = ''
    user.profession = ''
    user.experience = ''
    user.education = ''
    user.languages = ''
    user.extracurriculars = ''
    user.skills = ''
    user.interests = ''
    user.image_url = 'https://vsegda-pomnim.com/uploads/posts/2022-04/1649232783_41-vsegda-pomnim-com-p-pustoe-litso-foto-52.png'
    return user


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login') + '?next=' + request.url)
    return response


@app.route('/form', methods=['GET'])
@login_required
def form():
    user = User.query.filter_by(login=flask_login.current_user.login).first()
    return render_template('form.html', name=user.name, age=user.age,
                           country=user.country, town=user.town,
                           email=user.email, phone=user.phone,
                           profession=user.profession, languages=user.languages,
                           experience=user.experience, education=user.education,
                           extra=user.extracurriculars,
                           skills=user.skills, interests=user.interests,
                           image_url=user.image_url)


@app.route('/change_form', methods=['GET', 'POST'])
@login_required
def change_form():
    user = User.query.filter_by(login=flask_login.current_user.login).first()
    if request.args.get('name') != '' and len(request.args.get('name')) <= 1024:
        user.name = request.args.get('name')
    if request.args.get('age') != '' and len(request.args.get('age')) <= 1024:
        user.age = request.args.get('age')
    if request.args.get('country') != '' and len(request.args.get('country')) <= 1024:
        user.country = request.args.get('country')
    if request.args.get('town') != '' and len(request.args.get('town')) <= 1024:
        user.town = request.args.get('town')
    if request.args.get('email') != '' and len(request.args.get('email')) <= 1024:
        user.email = request.args.get('email')
    if request.args.get('phone') != '' and len(request.args.get('phone')) <= 1024:
        user.phone = request.args.get('phone')
    if request.args.get('profession') != '' and len(request.args.get('profession')) <= 1024:
        user.profession = request.args.get('profession')
    if request.args.get('experience') != '' and len(request.args.get('experience')) <= 1024:
        user.experience = request.args.get('experience')
    if request.args.get('education') != '' and len(request.args.get('education')) <= 1024:
        user.education = request.args.get('education')
    if request.args.get('languages') != '' and len(request.args.get('languages')) <= 1024:
        user.languages = request.args.get('languages')
    if request.args.get('skills') != '' and len(request.args.get('skills')) <= 1024:
        user.skills = request.args.get('skills')
    if request.args.get('interests') != '' and len(request.args.get('interests')) <= 1024:
        user.interests = request.args.get('interests')
    if request.args.get('image_url') != '' and len(request.args.get('image_url')) <= 1024:
        user.image_url = request.args.get('image_url')
    if request.args.get('extra') != '' and len(request.args.get('extra')) <= 1024:
        user.extracurriculars = request.args.get('extra')
    db.session.commit()

    return render_template('form.html', name=user.name, age=user.age,
                           country=user.country, town=user.town,
                           email=user.email, phone=user.phone,
                           profession=user.profession, languages=user.languages,
                           experience=user.experience, education=user.education,
                           extra=user.extracurriculars,
                           skills=user.skills, interests=user.interests,
                           image_url=user.image_url)


kitoptions = {
    "enable-local-file-access": None
}


@app.route('/cv', methods=['GET', 'POST'])
@login_required
def cv():
    user = User.query.filter_by(login=flask_login.current_user.login).first()
    try:
        pdf_template = render_template('cv.html', name=user.name, age=user.age,
                                       country=user.country, town=user.town,
                                       email=user.email, phone=user.phone,
                                       profession=user.profession, languages=user.languages,
                                       experience=user.experience, education=user.education,
                                       extra=user.extracurriculars,
                                       skills=user.skills, interests=user.interests,
                                       image_url=user.image_url)
        pdfkit.from_string(pdf_template, f'cv{flask_login.current_user.id}.pdf', options=kitoptions)

        return render_template('cv.html', name=user.name, age=user.age,
                               country=user.country, town=user.town,
                               email=user.email, phone=user.phone,
                               profession=user.profession, languages=user.languages,
                               experience=user.experience, education=user.education,
                               extra=user.extracurriculars,
                               skills=user.skills, interests=user.interests,
                               image_url=user.image_url)
    except Exception as e:
        return str(e)


@app.route('/download')
@login_required
def download():
    try:
        exact_path = f'/Users/antonina/PycharmProjects/homework_site/cv{flask_login.current_user.id}.pdf'
        return send_file(exact_path, as_attachment=True)
    except Exception as e:
        return str(e)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=90)
