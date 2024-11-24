from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length

class FormularioLogin(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=3, max=150)])
    contrasena = PasswordField('Contraseña', validators=[DataRequired()])
    enviar = SubmitField('Iniciar sesión')

class FormularioRegistro(FlaskForm):
    nombre_usuario = StringField('Nombre de usuario', validators=[DataRequired(), Length(min=3, max=150)])
    contrasena = PasswordField('Contraseña', validators=[DataRequired()])
    rol = SelectField('Rol', choices=[('user', 'Usuario'), ('editor', 'Editor'), ('admin', 'Administrador')], validators=[DataRequired()])
    enviar = SubmitField('Registrarse')
