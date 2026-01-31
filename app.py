from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from config import Config
from datetime import datetime


app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ================= USER MODEL =================

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    portfolio_url = db.Column(db.String(300), nullable=True)
    # user → requests
    requests = db.relationship('Request', backref='client', lazy=True)

    # provider → applications
    applications = db.relationship('Application', backref='provider', lazy=True)


# ================= REQUEST MODEL =================

class Request(db.Model):
    __tablename__ = 'requests'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Pending')
    client_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    applications = db.relationship('Application', backref='request', lazy=True)


# ================= APPLICATION MODEL =================

class Application(db.Model):
    __tablename__ = 'applications'

    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('requests.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)

    # Prevent same provider applying twice
    __table_args__ = (
        db.UniqueConstraint('provider_id', 'request_id', name='unique_provider_request'),
    )


# ================= LOGIN LOADER =================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ================= ROUTES =================

@app.route('/')
def index():
    return render_template('index.html')


# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        portfolio_url = None
        if role == 'provider':
            portfolio_url = request.form.get('portfolio_url')

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(username=name, email=email, password=hashed_pw, role=role, portfolio_url=portfolio_url)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ---------- LOGIN ----------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)

            if user.role == 'client':
                return redirect(url_for('client_dashboard'))
            else:
                return redirect(url_for('provider_requests'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')


# ---------- LOGOUT ----------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ---------- CLIENT DASHBOARD ----------
@app.route('/client-dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        return "Access Denied"
    return render_template('client_dashboard.html')


# ---------- PROVIDER: VIEW ALL REQUESTS ----------
@app.route('/provider/requests')
@login_required
def provider_requests():
    if current_user.role != 'provider':
        flash("Access denied.", "danger")
        return redirect('/')

    requests_list = Request.query.order_by(Request.created_at.desc()).all()
    return render_template('provider_requests.html', requests=requests_list)


# ---------- PROVIDER: APPLY TO REQUEST ----------
@app.route('/provider/request/<int:request_id>/apply', methods=['POST'])
@login_required
def apply_to_request(request_id):
    if current_user.role != 'provider':
        flash("Access denied.", "danger")
        return redirect('/')

    price = request.form.get('price')

    if not price:
        flash("Please enter a price.", "danger")
        return redirect(url_for('provider_requests'))

    # Stop duplicate applications
    existing = Application.query.filter_by(
        provider_id=current_user.id,
        request_id=request_id
    ).first()

    if existing:
        flash("You already applied to this request!", "warning")
        return redirect(url_for('provider_requests'))

    application = Application(
        provider_id=current_user.id,
        request_id=request_id,
        price=float(price)
    )

    db.session.add(application)
    db.session.commit()

    flash("Application submitted!", "success")
    return redirect(url_for('provider_requests'))


# ---------- CLIENT: CREATE REQUEST ----------
@app.route('/client/request/new', methods=['GET', 'POST'])
@login_required
def create_request():
    if current_user.role != 'client':
        return "Access Denied"

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        new_request = Request(
            title=title,
            description=description,
            client_id=current_user.id
        )

        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('client_requests'))

    return render_template('new_request.html')


# ---------- CLIENT: VIEW OWN REQUESTS ----------
@app.route('/client/requests')
@login_required
def client_requests():
    if current_user.role != 'client':
        return "Access Denied"

    requests_list = Request.query.filter_by(client_id=current_user.id).all()
    return render_template('client_requests.html', requests=requests_list)


# ---------- CLIENT: VIEW PROVIDER APPLICATIONS ----------
@app.route('/client/request/<int:request_id>/applications')
@login_required
def view_applications(request_id):
    if current_user.role != 'client':
        return "Access Denied"

    req = Request.query.get_or_404(request_id)

    if req.client_id != current_user.id:
        return "Unauthorized"

    applications = req.applications
    return render_template('client_applications.html', req=req, applications=applications)


if __name__ == '__main__':
    app.run()
