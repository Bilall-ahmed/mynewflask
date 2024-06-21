
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import random
import smtplib
from email.message import EmailMessage
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from botocore.exceptions import ClientError
from flask import jsonify
import uuid
 
app = Flask(__name__)
 
# DynamoDB Configuration
dynamodb = boto3.resource('dynamodb', region_name='ap-south-1',
                          aws_access_key_id='AKIATCKANF5PP3PVDJHP',
                          aws_secret_access_key='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')
table = dynamodb.Table('mydynamodbflask')
app.secret_key = 'MYAbOxeySQTDwy93f2I9cG9sSekY9xUPAA48wlBJ'
 
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")
 
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
 
def send_otp_email(email):
    otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
 
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('bilall3051@gmail.com', 'bsml zytu lgbj ltkt')
 
    msg = EmailMessage()
    msg['Subject'] = "OTP Verification"
    msg['From'] = 'bilall3051@gmail.com'
    msg['To'] = email
    msg.set_content("Your OTP is: " + otp)
 
    server.send_message(msg)
    server.quit()
 
    return otp
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = generate_password_hash(form.password.data)
 
        # Send OTP
        otp = send_otp_email(email)
        session['otp'] = otp
        session['name'] = name
        session['email'] = email
        session['password'] = password
 
        return redirect(url_for('verify_otp'))
 
    return render_template('register.html', form=form)
 
@app.route('/send_otp', methods=['GET'])
def send_otp():
    if request.method == 'GET':
        email = request.args.get('email')
        if email:
            # Send OTP
            otp = send_otp_email(email)
            session['otp'] = otp
            return jsonify({'success': True})
    return jsonify({'success': False})
 
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        if 'otp' not in session:
            flash('OTP verification failed. Please try again.')
            return redirect(url_for('register'))
 
        otp = request.form['otp']
 
        if otp == session['otp']:
            # If OTP is verified, continue with registration
            name = session['name']
            email = session['email']
            password = session['password']
            user_id = str(uuid.uuid4())
 
            try:
                table.put_item(
                    Item={
                        'id': user_id,
                        'email': email,
                        'name': name,
                        'password': password
                    }
                )
            except ClientError as e:
                # Log the error message
                print(f"Error creating account: {e.response['Error']['Message']}")
                flash(f"Error creating account: {e.response['Error']['Message']}")
                return redirect(url_for('register'))
 
            session.pop('otp')  # Clear OTP from session after successful verification
            session.pop('name')  # Clear name from session after registration
            session.pop('email')  # Clear email from session after registration
            session.pop('password')  # Clear password from session after registration
 
            flash('OTP verified. Account created successfully. Please login.')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('verify_otp'))
 
    return render_template('verify_otp.html')
 
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
 
        try:
            response = table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(email)
            )
            user = response['Items']
            if user:
                user = user[0]
            else:
                user = None
        except ClientError as e:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))
 
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))
 
    return render_template('login.html', form=form)
 
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
 
if __name__ == '__main__':
    app.run(debug=True)
 