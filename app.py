from flask import Flask,render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
# To get access of specific method for User
from flask_login import UserMixin
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SECRET_KEY'] = '57ed03707e8caaa7d986bdac' # WTForm CSRF Protection
# Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
login_manager.login_message_category='info'
# DB Configuration
db = SQLAlchemy(app) # Initialize instance for the SQLAlchemy class

# To Load the Actual User from the ID stored in session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Model
class User(db.Model,UserMixin):
    id = db.Column(db.Integer(),primary_key=True)
    username = db.Column(db.String(length=30),nullable=False,unique=True)
    email_address = db.Column(db.String(length=50),nullable=False,unique=True)
    password_hash = db.Column(db.String(length=60),nullable=False)
    budget = db.Column(db.Integer(),nullable=False,default=1000)
    items = db.relationship('Item',backref='owned_user',lazy=True)
    @property
    def prettier_budget(self):
        if len(str(self.budget)) >= 4:
            return f'{str(self.budget)[:-3]},{str(self.budget)[-3:]}$'
        else:
            return f"{self.budget}$"
    @property
    def password(self):
        return self.password_hash
    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self,given_password):
        return bcrypt.check_password_hash(self.password_hash,given_password)
    def can_purchase(self,item):
        return self.budget >= item.price
    def can_sell(self,item):
        return item in self.items

class Item(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=30),nullable=False,unique=True)
    price = db.Column(db.Integer(),nullable=False)
    barcode = db.Column(db.String(length=12),nullable=False,unique=True)
    description = db.Column(db.String(length=1024),nullable=False,unique=True)
    owner = db.Column(db.Integer(),db.ForeignKey('user.id'))
    def __repr__(self):
        return f"Item {self.name}"

# Purchase    
class PurchaseItemForm(FlaskForm):
    submit = SubmitField(label='Purchase')

# Sell
class SellItemForm(FlaskForm):
    submit = SubmitField(label='Sell')

# Form
class RegisterForm(FlaskForm):
    # Custom Validator
    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already in use! Please try a different username')
    def validate_email(self,email_address):
        email_address = User.query.filter_by(email_address=email_address.data).first()
        if email_address:
            raise ValidationError('Email address already in use! Please try a different email address')
    username = StringField(label='User Name',validators=[Length(min=2,max=30),DataRequired()])
    email_address = StringField(label='Email Address',validators=[Email(),DataRequired()])
    password=PasswordField(label='Password',validators=[Length(min=6),DataRequired()])
    confirmPassword=PasswordField(label='Confirm Password',validators=[EqualTo('password'),DataRequired()])
    submit=SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    username = StringField(label='User Name',validators=[DataRequired()])
    password=PasswordField(label='Password',validators=[DataRequired()])
    submit=SubmitField(label='Sign In')

# Route
@app.route('/')
@app.route('/home')
def hello():
    return render_template('home.html')

@app.route('/market',methods=['POST','GET'])
@login_required
def market():
    purchaseForm = PurchaseItemForm()
    sellingForm = SellItemForm()
    if request.method == 'POST':
        if purchaseForm.validate_on_submit():
            purchased_item = request.form.get('purchase_item')
            p_item_object = Item.query.filter_by(name=purchased_item).first()
            if p_item_object:
                if current_user.can_purchase(p_item_object):
                    p_item_object.owner = current_user.id
                    current_user.budget -= p_item_object.price
                    db.session.commit()
                    flash(f"Congratulations! You Purchased {p_item_object.name} for {p_item_object.price}.",category='success')
                else:
                    flash(f"Unfortunately, You don't have enough money to purchase {p_item_object.name}",category='danger')
                return redirect(url_for('market'))  
        if sellingForm.validate_on_submit():
            sold_item = request.form.get('sold_item')
            s_item_object = Item.query.filter_by(name=sold_item).first()
            if s_item_object:
                if current_user.can_sell(s_item_object):
                    s_item_object.owner = None
                    current_user.budget += s_item_object.price
                    db.session.commit()
                    flash(f"Congratulations! You Sold {s_item_object.name} for {s_item_object.price}.",category='success')
                else:
                    flash(f"Something went wrong with selling {s_item_object.name}",category='danger')
                return redirect(url_for('market'))   
    if request.method == "GET":
        items = Item.query.filter_by(owner=None) # DB
        owned_items = Item.query.filter_by(owner=current_user.id)
        return render_template('market.html',items = items,purchaseForm = purchaseForm,owned_items = owned_items,sellingForm =sellingForm)

@app.route('/register',methods=['POST','GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,email_address=form.email_address.data,password=form.password.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f'Account Created Successfully! You are now logged in as {user_to_create.username}',category='success'),
        return redirect(url_for('market'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f"There was an error with creating the user: {err_msg}", category='danger')
    return render_template('register.html',form=form)

@app.route('/login',methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f'Success! You are logged in as : {user.username}',category='success'),
            return redirect(url_for('market'))
        else:
            flash('Username or Password do not match! Please try again',category='danger')

    return render_template('login.html',form=form)
@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out!",category='info')
    return redirect(url_for('hello'))

# DOCUMENTATION
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)