from flask import Flask,redirect,url_for,render_template,request, session, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy 
import json  
from datetime import date
from datetime import timedelta, datetime
from flask_mail import Mail
from flask_mail import Message 
from werkzeug.security import generate_password_hash, check_password_hash
import re 
from functools import wraps
import itsdangerous
import os 
import time
import random
import calendar
from collections import defaultdict 
from sqlalchemy.orm import load_only
from sqlalchemy import or_
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import qrcode 
from flask import send_file
from PIL import Image, ImageDraw, ImageFont
import io
from io import BytesIO 
from sqlalchemy import BLOB
import base64
import hashlib
from sqlalchemy.orm import joinedload 
from sqlalchemy import LargeBinary, Table
from babel.dates import format_date
from math import ceil   


app=Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:JQdxhVRaOliOVDWnHMQVuMcVyzZwhYwH@roundhouse.proxy.rlwy.net:52905/railway'
# HACERLO en local (Guille): app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Estabilisador12345@localhost/people'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://dbplatacero_user:OOQNe6aLZkZuqoCbUhZz8pGPPo19hshc@dpg-cu6plmq3esus73fd0nog-a.oregon-postgres.render.com/dbplatacero"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.secret_key = "tu_clave_secreta"
app.permanent_session_lifetime = timedelta(minutes=30) # La sesión expira en 30 minutos
db=SQLAlchemy(app)



# Configuración para enviar correos electrónicos 

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'plattformacero01@gmail.com' 
app.config['MAIL_DEFAULT_SENDER'] = 'plattformacero01@gmail.com'
app.config['MAIL_PASSWORD'] = 'kangmnoerusqxrba'

# Configuración del generador de tokens
s = itsdangerous.URLSafeTimedSerializer(app.secret_key)
#Cookie sameSite 
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True  # Asegúrate de que esté habilitado para HTTPS



mail = Mail(app)



# Modelo para roles
class rol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)

# Modelo para registro de usuarios
class registro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    correo = db.Column(db.String(50), unique=True, nullable=False)
    contrasena = db.Column(db.String(2000), nullable=False)
    rol_id = db.Column(db.Integer, db.ForeignKey('rol.id', ondelete="CASCADE"), nullable=False)

    # Relación con roles
    rol = db.relationship('rol', backref='usuarios') 
    
    #Método para verificar contrasena 
    def verify(self, contrasena):
        return check_password_hash(self.contrasena_hash, contrasena)



# Modelo para personas
class persona(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(50), nullable=False)
    apellidos = db.Column(db.String(50), nullable=False)
    tipo_documento = db.Column(db.String(20), nullable=False) 
    numero_doc=db.Column(db.String(12),nullable=False)
    fecha_nacimiento = db.Column(db.Date, nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    sexo = db.Column(db.String(10), nullable=False)
    direccion_residencia = db.Column(db.String(100), nullable=False)
    barrio = db.Column(db.String(50), nullable=False)
    numero_telefono = db.Column(db.String(15), nullable=False)
    uso_imagenes = db.Column(db.String(10))
    nivel_educativo = db.Column(db.String(50), nullable=False)
    grupo_poblacional = db.Column(db.String(50), nullable=False)

    # Campos de información de salud
    eps = db.Column(db.String(50), nullable=False)
    nombre_acudiente = db.Column(db.String(50), nullable=False)
    numero_acudiente = db.Column(db.String(15), nullable=False)
    discapacidad = db.Column(db.String(50), nullable=True)
    enfermedad_cronica = db.Column(db.String(50), nullable=True)
    hospitalizaciones = db.Column(db.String(50), nullable=True)
    tratamientos = db.Column(db.String(50), nullable=True)
    condicion_fisica = db.Column(db.String(50), nullable=True)
    talla = db.Column(db.String(10), nullable=False)
    peso = db.Column(db.Integer, nullable=False)
    clases_inscritas = db.Column(db.Integer,default=0)
    clases_pagadas = db.Column(db.Integer, default=0) 
    
    #Control de pago/asistencia 
    
    clases_pay = db.Column(db.Integer, default=0)  # Estado de pago
    clases_ava = db.Column(db.Integer, default=0)  # Estado de disponibilidad de clases
    
    #Vista como completado de clases tomadas y guardadas como asistencia por un profesor
    clases_totales = db.Column(db.Integer, default=0)  # Total de clases en el plan
    clases_restantes = db.Column(db.Integer, default=0)  # Clases restantes
    
    # Relación con usuarios
    usuario_id = db.Column(db.Integer, db.ForeignKey('registro.id', ondelete="CASCADE"), nullable=False)
    usuario = db.relationship('registro', backref='personas') 
    
    #Parámetros propios (imagen de perfil y QR) 
    qr_person = db.Column(db.String, nullable=True)  # QR asociado a la persona
    info_qr = db.Column(LargeBinary, nullable=True)  # Información mutable referenciada por el QR


# Modelo para clases
class Clase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    duracion = db.Column(db.Integer, nullable=False)  # Duración de la clase en minutos
    hora_inicio=db.Column(db.String(10)) 
    hora_fin=db.Column(db.String(10)) 
    profesor_id = db.Column(db.Integer, db.ForeignKey('registro.id'), nullable=False)  # Relación con el profesor
    profesor = db.relationship('registro', backref='clases')  # Relación inversa
    ubicacion = db.Column(db.String(100), nullable=False)  # Ubicación de la clase
    fecha_programada = db.Column(db.String(100), nullable=False)  # Fecha y hora de la clase
    descripcion = db.Column(db.String(200), nullable=False)  # Descripción de la clase
    numero_cupos = db.Column(db.Integer, nullable=False)  # Número de cupos disponibles
    estado = db.Column(db.String(20), nullable=False, default="pendiente")  # Estado de la clase 
    lista = db.Column(db.Text)
    # Relación con personas que asisten a la clase
    asistentes = db.relationship('persona', secondary='asistencia', backref='clases_asistidas')    

# Tabla intermedia para asistencia a clases
asistencia = db.Table(
    'asistencia',
    db.Column('persona_id', db.Integer, db.ForeignKey('persona.id', ondelete="CASCADE"), primary_key=True),
    db.Column('clase_id', db.Integer, db.ForeignKey('clase.id', ondelete="CASCADE"), primary_key=True)
)


# Modelo para información financiera
class InformacionFinanciera(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nivel_inscripcion = db.Column(db.String(50), nullable=False)
    metodo_pago = db.Column(db.String(50), nullable=False)
    verificacion = db.Column(db.String(50), nullable=False)

    # Relación con personas
    persona_id = db.Column(db.Integer, db.ForeignKey('persona.id', ondelete="CASCADE"), nullable=False)
    persona = db.relationship('persona', backref='informacion_financiera')
   
#Modelo de consignación de toma de asistencias
class AsistenciaClase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clase_id = db.Column(db.Integer, db.ForeignKey('clase.id', ondelete="CASCADE"), nullable=False)
    persona_id = db.Column(db.Integer, db.ForeignKey('persona.id', ondelete="CASCADE"), nullable=False)
    presente = db.Column(db.Boolean, nullable=False)

    clase = db.relationship('Clase', backref='asistencias')
    persona = db.relationship('persona', backref='asistencias_clase')
 
# Modelo para la tabla de asistencia
class AsistenciaTotal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, nullable=False)
    clase_id = db.Column(db.Integer, db.ForeignKey('clase.id'), nullable=False)
    asistentes = db.Column(db.Integer, nullable=False)
    ausentes = db.Column(db.Integer, nullable=False)

    # Relación con la clase
    clase = db.relationship('Clase', backref='asistencias_totales')     
     
class Descuento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    porcentaje = db.Column(db.Integer, nullable=False)
    code = db.Column(db.String(50), nullable=False)
    habilitado = db.Column(db.String(2), default="SI")

class cursos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(200), nullable=False)
    precio = db.Column(db.Integer, nullable=False)  # Precio principal
    precio2 = db.Column(db.String(20), nullable=True)  # Precio alternativo 1
    precio3 = db.Column(db.Integer, nullable=True)


class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(50), nullable=False)
    apellidos = db.Column(db.String(50), nullable=False)
    cargo = db.Column(db.String(50), nullable=False)
    factor1 = db.Column(db.Float, nullable=True)  # Factor adicional para otros cálculos, si necesario
    factor2 = db.Column(db.Float, nullable=True)  # Segundo factor adicional

    # Relación con el registro de usuarios
    registro_id = db.Column(db.Integer, db.ForeignKey('registro.id', ondelete="CASCADE"), nullable=False, unique=True)
    registro = db.relationship('registro', backref='teacher_profile')



   
     
# Creación de la base de datos y tablas
with app.app_context():
    db.create_all()
    
    
    
    
#Métodos para mostrar mensajes 

def set_message(category, message):
    session['message'] = (category, message)

def get_message():
    message = session.pop('message', None)
    return message

@app.context_processor
def inject_get_message():
    return dict(get_message=get_message)


  
#Decorador para proteger rutas
def login_requerido(f):
    @wraps(f)
    def decorador(*args, **kwargs): 
        if "user_id" not in session:
            set_message("error", "Debe iniciar sesión para acceder a esta página.")
            return redirect(url_for("login")) 
        return f(*args, **kwargs) 
    return decorador
    
    
@app.route('/',methods=['GET','POST'])
def home():
    if request.method=='POST':
        # Handle POST Request here
        return render_template('login.html')
    return render_template('login.html')

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        #obtener valor username de forma segura
        username = request.form.get("username")
        contrasena = request.form.get("password")        

        if not username: 
            
            set_message("error", "Debe ingresar un nombre de usuario") 
            
            return render_template("login.html")        
        
        # Consultar si existe el usuario
        user = registro.query.filter_by(correo=request.form["username"]).first()
        #contrasena=request.form["password"]  

 
        # Validar si el usuario existe y la contrasena coincide
        if user and check_password_hash(user.contrasena, contrasena):
            session.permanent = True # Sesión permanente en el tiempo de
            session["user_id"] = user.id 
            session["correo"] = user.correo
            
            #Redirigir según el rol existente 
            if user.rol_id== 0: 
                print("Entra como rol cero")
                #generar código de verificación para administradores
                codigo_verificacion=random.randint(100000,999999)
                session["codigo_verificacion"]=codigo_verificacion #Almacenar código en la session 
                #Enviar código por correo
                asunto="Código de verificación"
                cuerpo= f"Tu código de verificación es: {codigo_verificacion}.Este código es válido por 5 minutos"
                enviar_correo(user.correo, asunto, cuerpo)
                
                set_message("info","Código de verificación enviado por correo")
                
                return render_template("verificar_codigo.html") 
            
            elif user.rol_id==1:
                return render_template("nav_user.html") 
            
            elif user.rol_id==2: 
                
                return render_template("nav_teacher.html")

            else:
                return("Rol no especificado")
        
        flash("Credenciales Invalidas", "error")
        return render_template("login.html")
    
    return render_template("login.html") 


#Verificación de administrador(): 
def es_admin():
    user_id = session.get("user_id")
    user = registro.query.get(user_id)
    return user and user.rol_id == 0 # id es cero (es admin) 


def enviar_correo(destinatario, asunto, cuerpo):
    mensaje = Message(asunto, recipients=[destinatario])
    mensaje.body = cuerpo
    try:
        mail.send(mensaje)
        return True
    except Exception as e:
        print(e)
        return False


@app.route("/solicitar_restablecimiento", methods=["GET", "POST"])
def solicitar_restablecimiento():
    if request.method == "POST":
        correo = request.form.get("correo")
        
        if not correo:
            set_message("error","Por favor, ingrese un correo electrónico.")
            return render_template("solicitar_restablecimiento.html")

        # Verificar si el usuario existe
        user = registro.query.filter_by(correo=correo).first()
        if not user:
            set_message("error", "No se encontró una cuenta con ese correo electrónico.")
            return render_template("solicitar_restablecimiento.html")

        # Generar token seguro con tiempo de expiración (3600 segundos = 1 hora)
        token = s.dumps(correo, salt='restablecer-contrasena')

        # Crear enlace con el token
        enlace = url_for("restablecer_contrasena", token=token, _external=True)

        # Enviar correo electrónico con el enlace
        mensaje = Message("Restablecimiento de Contraseña", sender="plattformacero01@gmail.com", recipients=[correo])
        mensaje.body = f"Para restablecer su contraseña, haga clic en el siguiente enlace: {enlace}"
        mail.send(mensaje)

        set_message("success", "Se ha enviado un enlace para restablecer su contraseña. Por favor, revise su correo electrónico.")
        return redirect(url_for("login"))

    return render_template("solicitar_restablecimiento.html")  # Formulario para solicitar restablecimiento 



@app.route("/restablecer_contrasena/<token>", methods=["GET", "POST"])
def restablecer_contrasena(token):
    try:
        # Verificar el token (expira en 1 hora)
        correo = s.loads(token, salt='restablecer-contrasena', max_age=3600)
    except itsdangerous.SignatureExpired:
        set_message("error","El enlace para restablecer la contraseña ha expirado.")
        return redirect(url_for("solicitar_restablecimiento"))

    if request.method == "POST":
        nueva_contrasena = request.form["nueva_contrasena"]
        confirmar_contrasena = request.form["confirmar_contrasena"]

        # Verificar si las contraseñas coinciden
        if nueva_contrasena != confirmar_contrasena:
            print("Las contraseñas no coinciden. Inténtelo nuevamente.", "error")
            return render_template("restablecer_contrasena.html", token=token)

        # Verificar el usuario por correo
        user = registro.query.filter_by(correo=correo).first()
        if user:
            # Actualizar la contraseña con un hash seguro
            user.contrasena = generate_password_hash(nueva_contrasena)
            db.session.commit()

            print("La contraseña ha sido restablecida. Ahora puede iniciar sesión.", "success")
            return redirect(url_for("login"))

        print("Hubo un error al restablecer la contraseña. Inténtelo nuevamente.", "error")
        return redirect(url_for("solicitar_restablecimiento"))

    return render_template("restablecer_contrasena.html", token=token)  # Formulario para restablecer contraseña


# Ruta para el restablecimiento de contraseña por parte del administrador
@app.route("/cambiar_contrasena/<int:id>", methods=["GET", "POST"])
#@es_admin  # Asegura que solo administradores pueden acceder
def cambiar_contrasena(id):
    # Obtener el usuario por ID
    user = registro.query.get(id)
    if not user:
        set_message("error","Usuario no encontrado.")
        return redirect(url_for("gestion_usuarios"))

    if request.method == "POST":
        nueva_contrasena = request.form["nueva_contrasena"]
        confirmar_contrasena = request.form["confirmar_contrasena"]

        # Verificar si las contraseñas coinciden
        if nueva_contrasena != confirmar_contrasena:
            set_message("error","Las contraseñas no coinciden. Inténtelo nuevamente.")
            return render_template("cambiar_contrasena.html", user=user)

        # Validar la seguridad de la contraseña
        mensaje_error = validar_contrasena(nueva_contrasena)
        if mensaje_error:
            set_message("error", mensaje_error)
            return render_template("cambiar_contrasena.html", user=user)

        # Actualizar la contraseña del usuario
        user.contrasena = generate_password_hash(nueva_contrasena)
        db.session.commit()

        set_message("success","La contraseña ha sido cambiada exitosamente.") 
        
        return redirect(url_for("gestion_usuarios"))

    # Mostrar el formulario para cambiar la contraseña
    return render_template("cambiar_contrasena.html", user=user) 


@app.route("/mew", methods=["POST"])
def mew():
    # Obtener los datos del formulario
    correo = request.form["correo"]
    contrasena = request.form["contrasena"] 
    confirmar_contrasena = request.form["confirmar_contrasena"]
    rol_id =  1 # Establecer el rol como False por defecto

    # Verificar si las contraseñas coinciden
    if contrasena != confirmar_contrasena:
        set_message("error","Las contraseñas no coinciden. Por favor, digitelas nuevamente") 
        
        return render_template("new.html", correo=correo)
    
    # Verificar si el correo ya está registrado en la base de datos
    existing_user = registro.query.filter_by(correo=correo).first()
    if existing_user:
        set_message("error","El correo electronico ya está registrado. Por favor, use otro")
        return render_template("new.html", correo=correo)
    
    #Validar la seguridad de la contraseña
    mensaje_error = validar_contrasena(contrasena)
    if mensaje_error:
        set_message("error", mensaje_error)
        return render_template("new.html", correo = correo)
    
    
    #Cifrar la contrasena antes de guardarla
    contrasena_hash=generate_password_hash(contrasena)
    
    # Si el correo no está registrado, crear un nuevo usuario
    new_user = registro(correo=correo, contrasena=contrasena_hash, rol_id=rol_id)
    
    # Agregar el nuevo usuario a la sesión de la base de datos
    db.session.add(new_user)
    # Confirmar los cambios en la base de datos
    db.session.commit()
    
    # Redireccionar a la página de inicio de sesión después del registro exitoso
    return redirect(url_for("login")) 


# Función para validar contraseñas según los requisitos
def validar_contrasena(contrasena):
    # Verificar longitud mínima de 10 caracteres
    msjj=  "La contrasena debe tener al menos 10 caracteres, una letra mayúscula, un número y al menos un carácter especial (por ejemplo, !, @, #, etc.)."
    if len(contrasena) < 10:
        return msjj
    # Verificar que contenga al menos una letra mayúscula
    if not re.search(r'[A-Z]', contrasena):
        return msjj    
    # Verificar que contenga al menos un número
    if not re.search(r'\d', contrasena):
        return msjj    
    # Verificar que contenga al menos un carácter especial
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', contrasena):
        return msjj
    return None  # Si no hay errores, devolver None


if __name__ == '__main__':
    
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run(port=5000,debug=True)
    
