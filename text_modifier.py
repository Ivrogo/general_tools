import tkinter as tk
import hashlib
import secrets
import string

def convertir_a_mayusculas():
    entrada_texto = entrada_var.get()
    resultado = entrada_texto.upper()
    resultado_var.set(resultado)
    actualizar_texto(resultado, texto_resultado_texto)

def convertir_a_minusculas():
    entrada_texto = entrada_var.get()
    resultado = entrada_texto.lower()
    resultado_var.set(resultado)
    actualizar_texto(resultado, texto_resultado_texto)

def alternar_mayusculas_minusculas():
    entrada_texto = entrada_var.get()
    resultado = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(entrada_texto))
    resultado_var.set(resultado)
    actualizar_texto(resultado, texto_resultado_texto)


def generar_contrasena_aleatoria(encriptar=False, algoritmo=None):
    longitud = 16  # Puedes ajustar la longitud según tus preferencias
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasena_aleatoria = ''.join(secrets.choice(caracteres) for _ in range(longitud))
    
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

        contrasena_aleatoria = hashed_contrasena

    resultado_var.set(contrasena_aleatoria)
    actualizar_texto(contrasena_aleatoria, texto_resultado_contrasena)

def actualizar_texto(texto, texto_widget):
    texto_widget.config(state=tk.NORMAL)
    texto_widget.delete(1.0, tk.END)
    texto_widget.insert(tk.END, texto)
    texto_widget.config(state=tk.DISABLED)

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Convertidor de Texto y Generador de Contraseñas")

# Crear variables de control
entrada_var = tk.StringVar()
resultado_var = tk.StringVar()

# Crear etiqueta y entrada de texto
etiqueta = tk.Label(ventana, text="Ingrese un texto:")
etiqueta.pack(pady=10)

entrada_texto = tk.Entry(ventana, textvariable=entrada_var)
entrada_texto.pack(pady=10)

# Crear botones para convertir
boton_convertir_mayusculas = tk.Button(ventana, text="Convertir a Mayúsculas", command=convertir_a_mayusculas)
boton_convertir_mayusculas.pack(pady=5)

boton_convertir_minusculas = tk.Button(ventana, text="Convertir a Minúsculas", command=convertir_a_minusculas)
boton_convertir_minusculas.pack(pady=5)

boton_alternar = tk.Button(ventana, text="Alternar Mayúsculas/Minúsculas", command=alternar_mayusculas_minusculas)
boton_alternar.pack(pady=5)

# Crear Text para mostrar el resultado de las operaciones de texto
texto_resultado_texto = tk.Text(ventana, height=3, width=40, state=tk.DISABLED)
texto_resultado_texto.pack(pady=10)

# Etiqueta y botones para generador de contraseñas
etiqueta_generador = tk.Label(ventana, text="Generador de Contraseñas:")
etiqueta_generador.pack(pady=10)

boton_generar_aleatoria = tk.Button(ventana, text="Generar Contraseña Aleatoria", command=lambda: generar_contrasena_aleatoria(encriptar=False))
boton_generar_aleatoria.pack(pady=5)

boton_encriptar_aleatoria_sha256 = tk.Button(ventana, text="Encriptar Aleatoria (SHA-256)", command=lambda: generar_contrasena_aleatoria(encriptar=True, algoritmo="SHA-256"))
boton_encriptar_aleatoria_sha256.pack(pady=5)

boton_encriptar_aleatoria_sha512 = tk.Button(ventana, text="Encriptar Aleatoria (SHA-512)", command=lambda: generar_contrasena_aleatoria(encriptar=True, algoritmo="SHA-512"))
boton_encriptar_aleatoria_sha512.pack(pady=5)

# Crear Text para mostrar el resultado de las contraseñas encriptadas
texto_resultado_contrasena = tk.Text(ventana, height=3, width=40, state=tk.DISABLED)
texto_resultado_contrasena.pack(pady=10)

# Iniciar el bucle principal de la interfaz gráfica
ventana.mainloop()
