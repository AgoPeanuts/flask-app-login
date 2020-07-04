from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_user, logout_user, login_required, current_user
from eb.models import UserOp
from eb.mod_auth.forms import LoginForm, RegisterForm, ChangeForm, DeleteForm

# create blueprint
auth = Blueprint('auth', __name__, url_prefix='/auth')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    # create RegisterForm instance
    form = RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            error = None
            # check the username has already existed
            chk_name = UserOp().get_user_name(form.username.data)
            if chk_name is not None:
                error = 'The username has already existed.'

            else:
                # check the email has already existed
                chk_email = UserOp().get_user_email(form.email.data)
                if chk_email is not None:
                    error = 'The email has already existed.'

            if error is None:
                UserOp().add_user(form.username.data, form.email.data, form.password.data)
                flash('Your account has been created!', 'success')
                return redirect(url_for('auth.login'))

            flash(error, 'danger')

    return render_template('auth/register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    # create LoginForm instance
    form = LoginForm()
    if request.method == 'POST':
        # check inputs' data
        if form.validate_on_submit():
            error = None

            # get user by email
            user = UserOp().get_user_email(form.email.data)

            # check if the user exists or not
            if user is None:
                error = 'Incorrect email.'
            # check is password correct using is_correct_password() func on Models
            elif not user.is_correct_password(form.password.data):
                error = 'Incorrect password.'

            if error is None:
                # set loged in user
                login_user(user)

                # next = request.args.get('next')
                # # is_safe_url should check if the url is safe for redirects.
                # if not is_safe_url(next):
                #     return abort(400)
                # return redirect(next or url_for('main.index'))
                return redirect(url_for('main.index'))
            flash(error, 'danger')

    return render_template('auth/login.html', form=form)


@auth.route('/logout')
def logout():
    logout_user()
    flash('Logged out!', 'success')
    return redirect(url_for('auth.login'))


@auth.route('/change', methods=['GET', 'POST'])
@login_required
def change():
    form = ChangeForm()

    if request.method == 'POST':
        if form.validate_on_submit():

            # get the user by current_user.id
            user = UserOp().get_user_id(current_user.id)

            if user is None:
                flash('Please login again.', 'danger')
                return redirect(url_for('auth.login'))

            elif not user.is_correct_password(form.password.data):
                flash('Incorrect password.', 'danger')

            else:
                # set new hashed password
                user.set_password(form.new_password.data)
                UserOp().update_user(user)
                flash('Your password has been changed!', 'success')

    return render_template('auth/change.html', form=form)


@auth.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    form = DeleteForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            user_id = current_user.id
            # logout
            logout_user()
            # get the user by current_user.id
            user = UserOp().get_user_id(user_id)

            if user is None:
                flash('Please login again.', 'danger')
                return redirect(url_for('auth.login'))

            UserOp().delete_user(user)
            flash('Your account has been deleted.', 'success')
            return redirect(url_for('auth.register'))

    return render_template('auth/delete.html', form=form)