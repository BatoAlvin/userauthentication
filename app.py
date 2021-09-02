from enum import unique
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


#Build an instance
app = Flask(__name__)

#Define uri for db

# app.config['SQLALCHEMY_DATABASE_URI']='postgresql://bnpettdlgzxipc:f24c2f3bf1532689f572752c2d457662bf36946370c2790fb604b076ee9cc832@ec2-18-235-45-217.compute-'
# app.config['SQLALCHEMY_DATABASE_URI']=os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI']="postgresql://bnpettdlgzxipc:f24c2f3bf1532689f572752c2d457662bf36946370c2790fb604b076ee9cc832@ec2-18-235-45-217.compute-1.amazonaws.com:5432/dda8kjrug1lh38"
app.config['SECRET_KEY'] = 'thisisasecretkey'


# app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:1234@localhost/students'
#Create object
db=SQLAlchemy(app)
bcrypt = Bcrypt(app)

#Allows our flask app to manage logging in and out features
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#Load user callback reloades user id stored in our callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Creating class for students
class User(db.Model,UserMixin):
 
  id=db.Column(db.Integer,primary_key=True)
  name=db.Column(db.String(20))
  email=db.Column(db.String(20))
  password=db.Column(db.String(255))


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=3, max=20)], render_kw={"placeholder": "Name"})

    email = StringField(validators=[InputRequired(), Length(
        min=3, max=20)], render_kw={"placeholder": "Email"}) 

    password = PasswordField(validators=[InputRequired(), Length (
        min=2, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register") 


    def validate_name(self, name):
        existing_user_name = User.query.filter_by(
            name=name.data).first()

        if existing_user_name:
            raise ValidationError(
                "User already exists. Please choose a different one"
            )    

class LoginForm(FlaskForm):
    # email = StringField(validators=[InputRequired(), Length(
    #     min=3, max=20)], render_kw={"placeholder": "Email"}) 

    name = StringField(validators=[InputRequired(), Length(
        min=3, max=20)], render_kw={"placeholder": "Name"}) 

    password = PasswordField(validators=[InputRequired(), Length (
        min=2, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login") 


#Build a get route for login form
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/dashboard')
    return render_template('login.html', form=form)

#Build a get route for register form
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(hashed_password)
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/')
    return render_template('register.html', form=form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')

if __name__ == "__main__":
    app.run(debug=True)    