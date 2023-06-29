from flask import Flask, render_template, redirect, flash, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    age = db.Column(db.Integer)
    password = db.Column(db.String(80), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Save')

class CalcForm(FlaskForm):
    a = IntegerField("A=")
    b = IntegerField("B=")
    submit = SubmitField('+')

class UserAddForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    age = IntegerField('Age', validators=[DataRequired()])
    submit = SubmitField('Save')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists! Please choose a different one.', 'danger')
            return redirect('/register')
        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect('/')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect('/')
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/')
@login_required
def home():
    user = {
        "username": current_user.username,
        "email": current_user.email,
    }
    return render_template('index.html', user=user)

@app.route('/users')
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/add',methods=["POST","GET"])
def users_add():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        age = request.form['age']
        password = "password"
        new_user = User(username=username,email=email,age=age,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/users')
    return render_template('users_add.html' )


@app.route('/users/edit/<int:id>',methods=["POST","GET"])
def users_edit(id):
    user = User.query.get_or_404(id)
    if request.method == "POST":
        user.username = request.form['username']
        user.email = request.form['email']
        user.age = request.form['age']
        db.session.commit()
        return redirect('/users')
    return render_template('users_edit.html', user=user)

@app.route('/users/delete/<int:id>',methods=["POST"])
def users_delete(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return redirect('/users')

@app.route("/profile", methods=['GET','POST'])
@login_required
def profile():
    form = ProfileEditForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(id=current_user.id).first()
        if not existing_user:
            return ""
        existing_user.username = form.username.data
        existing_user.email = form.email.data
        db.session.commit()
        flash('Edit success', 'success')
        return redirect('/profile')
    return render_template('profile.html', form=form)

@app.route("/users/add", methods=['GET','POST'])
def users_add():
    form = UserAddForm()


@app.route("/data", methods=["POST", 'GET'])
def check():
    return jsonify({
        "data": 'HI'
    })


@app.route("/calc", methods=["GET","POST"])
def calc():
    form = CalcForm()
    if form.validate_on_submit():
        a = form.a.data
        b = form.b.data
        result = a + b
        flash('Result = '+str(result))
        return redirect('/calc')
    return render_template('calc.html', form=form)


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error404.html')

@app.errorhandler(500)
def not_found_error(error):
    return render_template('error500.html')






if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
