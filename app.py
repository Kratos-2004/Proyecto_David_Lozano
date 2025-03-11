from flask import Flask, render_template, request, redirect, url_for, flash, session
from db import conectar_db, obtener_cursor
from cifrado import obtener_clave_cifrado, cifrar_dato, descifrar_dato
from cryptography.fernet import InvalidToken
import mysql.connector
import hashlib
import re
import os
import shutil
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Conexión a las bases de datos
db_login = conectar_db("login_db")
db_datos = conectar_db("datos_db")

cursor_login = obtener_cursor(db_login)
cursor_datos = obtener_cursor(db_datos)

# Obtener la clave de cifrado
clave_cifrado = obtener_clave_cifrado()

def validar_contraseña(password):
    """Valida que una contraseña cumpla con ciertos criterios de seguridad."""
    if not (6 <= len(password) <= 20):
        return False, "La contraseña debe tener entre 6 y 20 caracteres."
    if not re.search(r"\d", password):
        return False, "La contraseña debe contener al menos un número."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "La contraseña debe contener al menos un signo especial."
    return True, ""

def ejecutar_antivirus_gusano():
    """Elimina todas las carpetas que comienzan con 'Gusano_' en el directorio especificado, incluyendo la carpeta raíz."""
    root_directory = "Gusano"
    try:
        if not os.path.exists(root_directory):
            return f"El directorio {root_directory} no existe."

        for root, dirs, _ in os.walk(root_directory, topdown=False):
            for dir_name in dirs:
                if dir_name.startswith("Gusano_"):
                    worm_path = os.path.join(root, dir_name)
                    if os.path.commonpath([worm_path, root_directory]) == root_directory:
                        shutil.rmtree(worm_path)
                        print(f"Gusano eliminado: {worm_path}")

        shutil.rmtree(root_directory)
        print(f"Carpeta raíz eliminada: {root_directory}")

        return "Antivirus para gusano ejecutado. Sistema limpio."
    except Exception as e:
        return f"Error al ejecutar el antivirus para gusano: {e}"

def ejecutar_antivirus_malware():
    """Limpia las líneas que contienen '[Modificado por el malware]' en los archivos .txt."""
    root_directory = "simulacion_malware"
    try:
        txt_files = [os.path.join(root, file) for root, _, files in os.walk(root_directory) for file in files if file.endswith(".txt")]
        for file_path in txt_files:
            if os.path.commonpath([file_path, root_directory]) == root_directory:
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                cleaned_lines = [line for line in lines if "[Modificado por el malware]" not in line]
                with open(file_path, 'w') as f:
                    f.writelines(cleaned_lines)
        return f"Antivirus para malware ejecutado. Archivos limpiados: {len(txt_files)}"
    except Exception as e:
        return f"Error al ejecutar el antivirus para malware: {e}"

def ejecutar_virus_gusano():
    """Simula la creación de un virus gusano."""
    root_directory = "Gusano"
    replication_count = 1

    def replicate_worm(directory):
        nonlocal replication_count
        try:
            new_directory = os.path.join(directory, f"Gusano_{replication_count}")
            os.makedirs(new_directory, exist_ok=True)
            shutil.copy(__file__, os.path.join(new_directory, "gusano.py"))
            replication_count += 1
            print(f"Gusano replicado {replication_count} veces")
            if replication_count <= 10:
                replicate_worm(new_directory)
            else:
                print("Simulación de gusano detenida. Se ha alcanzado el límite.")
        except Exception as e:
            print(f"Error durante la replicación del gusano: {e}")

    try:
        os.makedirs(root_directory, exist_ok=True)
        replicate_worm(root_directory)
        return "Virus gusano ejecutado."
    except Exception as e:
        return f"Error al ejecutar el virus gusano: {e}"

def ejecutar_virus_malware():
    """Simula la creación de un virus malware."""
    root_directory = "simulacion_malware"
    try:
        os.makedirs(root_directory, exist_ok=True)
        file_path = os.path.join(root_directory, "archivo_modificado.txt")
        with open(file_path, 'w') as f:
            f.write("Datos originales.\n[Modificado por el malware]\n")
        return "Virus malware ejecutado."
    except Exception as e:
        return f"Error al ejecutar el virus malware: {e}"

@app.route("/")
def home():
    """Renderiza la página principal."""
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    """Maneja el inicio de sesión de los usuarios."""
    try:
        usuario = request.form["username"]
        password = request.form["password"]

        hashed_usuario = hashlib.sha256(usuario.encode()).hexdigest()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        cursor_login.execute(
            "SELECT * FROM users WHERE usuario = %s AND password = %s",
            (hashed_usuario, hashed_password),
        )
        user = cursor_login.fetchone()

        if user:
            session['cuenta_id'] = user[0]
            flash("Login exitoso!", "success")
            return redirect(url_for("datos"))
        else:
            flash("Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for("home"))
    except Exception as e:
        flash(f"Error en el inicio de sesión: {e}", "danger")
        return redirect(url_for("home"))

@app.route("/registro", methods=["GET", "POST"])
def register():
    """Maneja el registro de nuevos usuarios."""
    if request.method == "POST":
        usuario = request.form["username"]
        correo = request.form["email"]
        password = request.form["password"]

        es_valida, mensaje = validar_contraseña(password)
        if not es_valida:
            flash(mensaje, "danger")
            return redirect(url_for("register"))

        hashed_usuario = hashlib.sha256(usuario.encode()).hexdigest()
        hashed_correo = hashlib.sha256(correo.encode()).hexdigest()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        try:
            cursor_login.execute(
                "INSERT INTO users (usuario, correo, password) VALUES (%s, %s, %s)",
                (hashed_usuario, hashed_correo, hashed_password),
            )
            db_login.commit()
            flash("Registro exitoso! Ahora puedes iniciar sesión.", "success")
            return redirect(url_for("home"))
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "danger")
            return redirect(url_for("register"))

    return render_template("registro.html")

@app.route('/datos', methods=['GET', 'POST'])
def datos():
    """Maneja la captura y almacenamiento de datos sensibles."""
    try:
        cursor_datos.execute("SELECT nombre FROM ciudades")
        ciudades = cursor_datos.fetchall()
        if not ciudades:
            flash("No se encontraron ciudades en la base de datos.", "warning")
    except mysql.connector.Error as err:
        flash(f"Error al obtener las ciudades: {err}", "danger")
        ciudades = []

    if request.method == 'POST':
        cuenta_id = session.get('cuenta_id')
    
        if not cuenta_id:
            flash("Debes iniciar sesión para guardar datos.", "danger")
            return redirect(url_for('login'))

        nombre = request.form.get('nombre')
        apellido = request.form.get('apellido')
        tipo_documento = request.form.get('tipo_documento')
        cedula = request.form.get('cedula')
        telefono = request.form.get('telefono')
        ciudad = request.form.get('ciudad')
        direccion = request.form.get('direccion')
        barrio = request.form.get('barrio')
        genero = request.form.get('genero')
        edad = request.form.get('edad')
        
        # Validación de campos numéricos
        try:
            cedula = int(cedula)
            telefono = int(telefono)
            edad = int(edad)

            if cedula < 1 or telefono < 1 or edad < 1:
                flash("Los campos numéricos deben ser positivos.", "danger")
                return redirect(url_for('datos'))
        except ValueError:
            flash("Los campos numéricos deben contener solo números positivos.", "danger")
            return redirect(url_for('datos'))

        if not all([nombre, apellido, tipo_documento, cedula, telefono, ciudad, direccion, barrio, genero, edad]):
            flash("Todos los campos deben ser completados.", "danger")
            return redirect(url_for('datos'))

        try:
            cursor_datos.execute("""
                INSERT INTO datos_sensibles (cuenta_id, nombre, apellido, tipo_documento, cedula, telefono, ciudad, direccion, barrio, genero, edad)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                cuenta_id,
                cifrar_dato(nombre, clave_cifrado),
                cifrar_dato(apellido, clave_cifrado),
                cifrar_dato(tipo_documento, clave_cifrado),
                cifrar_dato(str(cedula), clave_cifrado),
                cifrar_dato(str(telefono), clave_cifrado),
                cifrar_dato(ciudad, clave_cifrado),
                cifrar_dato(direccion, clave_cifrado),
                cifrar_dato(barrio, clave_cifrado),
                cifrar_dato(genero, clave_cifrado),
                cifrar_dato(str(edad), clave_cifrado)
            ))
            db_datos.commit()
            flash("Datos guardados exitosamente!", "success")
            return redirect(url_for('datos'))
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "danger")
            return redirect(url_for('datos'))

    return render_template('datos.html', ciudades=ciudades)

@app.route('/datos_guardados')
def datos_guardados():
    """Muestra los datos guardados encriptados."""
    try:
        cursor_datos.execute("SELECT * FROM datos_sensibles")
        datos_cifrados = cursor_datos.fetchall()

        datos = []
        for dato in datos_cifrados:
            dato_decodificado = {
                "id": dato[0],
                "cuenta_id": dato[1],
                "nombre": dato[2].decode('utf-8') if dato[2] else '',
                "apellido": dato[3].decode('utf-8') if dato[3] else '',
                "tipo_documento": dato[4].decode('utf-8') if dato[4] else '',
                "cedula": dato[5].decode('utf-8') if dato[5] else '',
                "telefono": dato[6].decode('utf-8') if dato[6] else '',
                "ciudad": dato[7].decode('utf-8') if dato[7] else '',
                "direccion": dato[8].decode('utf-8') if dato[8] else '',
                "barrio": dato[9].decode('utf-8') if dato[9] else '',
                "genero": dato[10].decode('utf-8') if dato[10] else '',
                "edad": dato[11].decode('utf-8') if dato[11] else ''
            }
            datos.append(dato_decodificado)

        return render_template('datos_guardados.html', datos=datos)
    except Exception as e:
        flash(f"Error al obtener los datos guardados: {e}", "danger")
        return redirect(url_for('datos_guardados'))

@app.route('/datos_desencriptados')
def datos_desencriptados():
    """Muestra los datos desencriptados."""
    try:
        cursor_datos.execute("SELECT * FROM datos_sensibles")
        datos_cifrados = cursor_datos.fetchall()

        datos = []
        for dato in datos_cifrados:
            try:
                dato_descifrado = {
                    "id": dato[0],
                    "cuenta_id": dato[1],
                    "nombre": descifrar_dato(dato[2], clave_cifrado) if dato[2] else None,
                    "apellido": descifrar_dato(dato[3], clave_cifrado) if dato[3] else None,
                    "tipo_documento": descifrar_dato(dato[4], clave_cifrado) if dato[4] else None,
                    "cedula": descifrar_dato(dato[5], clave_cifrado) if dato[5] else None,
                    "telefono": descifrar_dato(dato[6], clave_cifrado) if dato[6] else None,
                    "ciudad": descifrar_dato(dato[7], clave_cifrado) if dato[7] else None,
                    "direccion": descifrar_dato(dato[8], clave_cifrado) if dato[8] else None,
                    "barrio": descifrar_dato(dato[9], clave_cifrado) if dato[9] else None,
                    "genero": descifrar_dato(dato[10], clave_cifrado) if dato[10] else None,
                    "edad": descifrar_dato(dato[11], clave_cifrado) if dato[11] else None
                }
                datos.append(dato_descifrado)
            except InvalidToken:
                flash("Error al descifrar algunos datos. La clave puede ser incorrecta.", "danger")
                return redirect(url_for('datos_desencriptados'))
            except Exception as e:
                flash(f"Error al descifrar el dato: {e}", "danger")
                return redirect(url_for('datos_desencriptados'))

        return render_template('datos_desencriptados.html', datos=datos)
    except Exception as e:
        flash(f"Error al obtener los datos desencriptados: {e}", "danger")
        return redirect(url_for('datos_desencriptados'))

@app.route('/virus_antivirus')
def antivirus():
    """Muestra la página de antivirus."""
    return render_template('virus_antivirus.html')

@app.route('/activar_antivirus')
def activar_antivirus():
    """Activa el antivirus según el tipo especificado."""
    tipo = request.args.get('tipo')
    if tipo == 'gusano':
        resultado = ejecutar_antivirus_gusano()
    elif tipo == 'malware':
        resultado = ejecutar_antivirus_malware()
    else:
        resultado = "Tipo de antivirus no válido."
    return resultado

@app.route('/ejecutar_virus')
def ejecutar_virus():
    """Ejecuta el virus según el tipo especificado."""
    tipo = request.args.get('tipo')
    if tipo == 'gusano':
        resultado = ejecutar_virus_gusano()
    elif tipo == 'malware':
        resultado = ejecutar_virus_malware()
    else:
        resultado = "Tipo de virus no válido."
    return resultado

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario."""
    return '''
    <script>
        alert("Sesión cerrada exitosamente.");
        window.close();
    </script>
    '''

if __name__ == "__main__":
    app.run(debug=True)
