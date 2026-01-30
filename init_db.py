from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


db = SQLAlchemy(app)


class Domain(db.Model):
    __tablename__ = 'domains'

    id = db.Column(db.Integer, primary_key=True)
    rank = db.Column(db.Integer, nullable=True)
    name = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), unique=True, nullable=False)

    def __repr__(self):
        return f'<Domain {self.domain}>'


with open('whitelist.csv', 'r') as whitelist:
    with app.app_context():
        db.create_all()

        for line in whitelist.readlines():
            name, domain = line.strip().split(',')

            if domain in [i[0] for i in domains]:
                continue

            dm = Domain(rank = 100,
                        name = name, 
                        domain = domain)

            db.session.add(dm)

        db.session.commit()