from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/flask_auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nombre de usuario"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Contraseña"})
    role = SelectField("Rol", choices=[("admin", "Administrador"), ("editor", "Editor"), ("user", "Usuario")])
    submit = SubmitField("Registrarse")

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("El nombre de usuario ya existe. Elige otro.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nombre de usuario"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Contraseña"})
    submit = SubmitField("Iniciar sesión")

@app.route('/')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('admin.html', users=users)
    elif current_user.role == 'editor':
        return render_template('editor.html')
    elif current_user.role == 'user':
        return render_template('user.html')
    else:
        return "Role invalido!", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Nombre de usuario o contraseña incorrectos.", "danger")
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash("Registro exitoso. Ahora puedes iniciar sesión.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.role = request.form.get('role')
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('dashboard'))
class Critica(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    deporte = db.Column(db.String(50), nullable=False)
    editor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Critica {self.title}>'

@app.route('/editor/criticas', methods=['GET', 'POST'])
@login_required
def gestionar_criticas():
    if current_user.role != 'editor':
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        deporte = request.form.get('deporte')
        nueva_critica = Critica(title=title, content=content, deporte=deporte, editor_id=current_user.id)
        db.session.add(nueva_critica)
        db.session.commit()
        flash("Crítica añadida exitosamente.", "success")
    
    criticas = Critica.query.all()
    return render_template('editor.html', criticas=criticas)

@app.route('/criticas/<deporte>')
def criticas_por_deporte(deporte):
    criticas = Critica.query.filter_by(deporte=deporte).all()
    return render_template('criticas.html', deporte=deporte, criticas=criticas)

@app.route('/eliminar_critica/<int:id>', methods=['POST'])
@login_required
def eliminar_critica(id):
    if current_user.role != 'editor':
        return redirect(url_for('dashboard'))

    critica = Critica.query.get_or_404(id)
    db.session.delete(critica)
    db.session.commit()
    flash("Crítica eliminada exitosamente.", "success")
    return redirect(url_for('gestionar_criticas'))



@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
