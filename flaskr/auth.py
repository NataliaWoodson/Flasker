import functools

from flask import (
  Blueprint, flash, g, redirect, render_template, request, session
)
from flask.helpers import url_for
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

#create bluepring named 'auth'
bp = Blueprint('auth', __name__, url_prefix='/auth')

#associates the URL '/register' with the register view function
@bp.route('/register', methods=('GET', 'POST'))
def register():
  if request.method == 'POST':
    #request.form is a dict mapping submitted keys and values. User will input username and password
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    error = None

    if not username:
      error = 'Username is required.'
    elif not password:
      error = 'Password is required.'

    if error is None:
      try:
        #takes a SQL query with '?' placeholders for any user input, and a tubple of values to replace the placeholders with
        db.execute(
          "INSERT INTO user (username, password) VALUES (?, ?)",
          (username, generate_password_hash(password)),
        )
        db.commit()
      except db.IntegrityError:
        error = f"User {username} is already registered."
      else:
        return redirect(url_for("auth.login"))
    #if validation fails, error is shown to the user
    flash(error)

  return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
  if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    error = None
    user = db.execute(
      'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()

    if user is None:
      error = 'Incorrect username.'
    elif not check_password_hash(user['password'], password):
      error = 'Incorrect password.'

    if error is None:
      session.clear()
      session['user_id'] = user['id']
      return redirect(url_for('index'))

    flash(error)

  return render_template('auth/login.html')

#registers a function that runs before the view function, no matter what URL is requested
@bp.before_app_request
#checks if a user id is stored in the session and gets that user's date from the database, storing it on g.user, which lasts for the length of the request. 
def load_logged_in_user():
  user_id = session.get('user_id')

  #If there is no user id, or if it doesn't exist, g.user will be 'none'
  if user_id is None:
    g.user = None
  else:
    g.user = get_db().execute(
      'SELECT * FROM user WHERE id = ?', (user_id,)
    ).fetchone()

@bp.route('/logout')
def logout():
  session.clear()
  return redirect(url_for('index'))

def login_required(view):
  @functools.wraps(view)
  def wrapped_view(**kwargs):
    if g.user is None:
      return redirect(url_for('auth.login'))

    return view(**kwargs)
  
  return wrapped_view
