from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class RegisterForm(FlaskForm):
    username = StringField('Username (2-20 characters)', validators=[DataRequired(message='Username is required.'), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(message='Email is required.'), Email()])
    password = PasswordField('Password (6 or more characters)', validators=[DataRequired(message='Password is required.'), Length(min=6)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(message='Confirm Password is required.'), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message='Email is required.'), Email()])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required.')])
    #remember = BooleanField('Remember me')
    submit = SubmitField('Login')


class ChangeForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    new_password = PasswordField('New Password (6 or more characters)', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('Confirm New Password',
                                     validators=[DataRequired(), EqualTo('new_password', message="Field must be equal to new password.")])
    submit = SubmitField('Change')


class DeleteForm(FlaskForm):
    submit = SubmitField('Delete my account')