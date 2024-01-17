import hashlib
import secrets
import string
import pymongo
import tkinter as tk
from tkinter import Tk, Button, Text, StringVar

# Establecemos conexión con MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")

# Seleccionamos una base de datos
db = client["gestor_contraseñas_db"]

# Seleccionamos una colección
contraseñas_collection = db["contraseñas"]

# Crear la interfaz gráfica
ventana = Tk()
ventana.title("Gestor de Contraseñas")

# Var para almacenar la contraseña generada encriptada
contrasena_actual = StringVar()

def actualizar_texto(texto, widget):
    widget.delete(1.0, "end")
    widget.insert("end", texto)
    
def generar_usuario():
    nombre = entry_nombre.get()
    apellido = entry_apellido.get()
    
    # Convertimos tanto nombre y apellido a minusculas y quitamos los espacios. 
    nombre = nombre.lower().replace(" ", "")
    apellido = apellido.lower().replace(" ", "")
    
    # Creamos el usuario en base al nombre + apellidos intercalados por un punto
    usuario = nombre + "." + apellido
    
     # Mostrar el nombre de usuario en la etiqueta
    label_resultado.config(text=f"Tu nombre de usuario es: {usuario}")
     

    
def generar_contrasena_aleatoria(encriptar=False, algoritmo=None):
    longitud = 24
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasena_aleatoria = ''.join(secrets.choice(caracteres) for _ in range(longitud))
    
    # Si se especifica encriptar y algoritmo, encriptar la contraseña
    if encriptar and algoritmo:
        salt = secrets.token_hex(16)
        contrasena = contrasena_aleatoria.encode('utf-8') + salt.encode('utf-8')

        if algoritmo == "SHA-256":
            hashed_contrasena = hashlib.sha256(contrasena).hexdigest()
        elif algoritmo == "SHA-512":
            hashed_contrasena = hashlib.sha512(contrasena).hexdigest()
        else:
            # En caso de algoritmo no reconocido, usar SHA-256 por defecto
            hashed_contrasena = hashlib.sha256(contrasena).hexdigest()

        # Mostrar la contraseña encriptada en la interfaz gráfica
        contrasena_actual.set(hashed_contrasena)
        actualizar_texto(hashed_contrasena, texto_resultado_contrasena)
    else:
        # Mostrar la contraseña generada en la interfaz gráfica
        contrasena_actual.set(contrasena_aleatoria)
        actualizar_texto(contrasena_aleatoria, texto_resultado_contrasena)

    # Devolver la contraseña generada o encriptada
    return contrasena_aleatoria if not encriptar else hashed_contrasena

def guardar_contrasena(encriptar=False, algoritmo=None):
    # Obtener la contraseña generada o encriptada
    contrasena = contrasena_actual.get()

    # Comprobar si la contraseña ya está encriptada
    if not contrasena.isnumeric() and contrasena.isalnum():
        # Si la contraseña ya está encriptada, no la encriptamos nuevamente
        contrasena_encriptada = contrasena
    else:
        # Si la contraseña no está encriptada, la encriptamos
        # Si se especifica encriptar y algoritmo, encriptar la contraseña
        if encriptar and algoritmo:
            salt = secrets.token_hex(16)
            contrasena = contrasena.encode('utf-8') + salt.encode('utf-8')

            if algoritmo == "SHA-256":
                contrasena_encriptada = hashlib.sha256(contrasena).hexdigest()
            elif algoritmo == "SHA-512":
                contrasena_encriptada = hashlib.sha512(contrasena).hexdigest()
            else:
                # En caso de algoritmo no reconocido, usar SHA-256 por defecto
                contrasena_encriptada = hashlib.sha256(contrasena).hexdigest()
        else:
            # Si no se especifica encriptar y algoritmo, usamos la contraseña tal cual
            contrasena_encriptada = contrasena

    # Guardar la contraseña encriptada en la colección de MongoDB
    nueva_contraseña = {"sitio": "generada_manualmente", "usuario": "usuario_manual", "contraseña": contrasena_encriptada}
    contraseñas_collection.insert_one(nueva_contraseña)

    # Mostrar un mensaje de éxito o realizar otras acciones según sea necesario
    print("Contraseña guardada con éxito.")

# Crear y colocar widgets en la ventana
tk.Label(ventana, text="Nombre:").pack()
entry_nombre = tk.Entry(ventana)
entry_nombre.pack()

tk.Label(ventana, text="Apellido:").pack()
entry_apellido = tk.Entry(ventana)
entry_apellido.pack()

btn_generar = tk.Button(ventana, text="Generar Usuario", command=generar_usuario)
btn_generar.pack()

label_resultado = tk.Label(ventana, text="")
label_resultado.pack()


# Crear un área de texto para mostrar la contraseña
texto_resultado_contrasena = Text(ventana, height=2, width=50)
texto_resultado_contrasena.pack()

# Crear un botón para generar y guardar la contraseña encriptada
boton_guardar_encriptada = Button(ventana, text="Guardar Contraseña Encriptada", command=lambda: guardar_contrasena(True, "SHA-256"))
boton_guardar_encriptada.pack()

# Crear un botón para generar y mostrar una contraseña aleatoria encriptada
boton_generar_encriptada = Button(ventana, text="Generar Contraseña Encriptada", command=lambda: generar_contrasena_aleatoria(True, "SHA-256"))
boton_generar_encriptada.pack()

# Crear un botón para generar y mostrar una contraseña aleatoria sin encriptar
boton_generar_normal = Button(ventana, text="Generar Contraseña Normal", command=lambda: generar_contrasena_aleatoria())
boton_generar_normal.pack()

# Ejecutar el bucle principal de la interfaz gráfica
ventana.mainloop()
