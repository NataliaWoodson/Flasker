import flaskr

app = flaskr.create_app()

from flaskr import db
with app.app_context():
    db.init_db()

app.run()
