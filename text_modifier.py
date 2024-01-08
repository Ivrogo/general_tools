import tkinter as tk
import hashlib
import secrets

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

def generar_contrasena_encriptada(algoritmo):
    entrada_texto = entrada_var.get()
    # Usar un salt aleatorio para mayor seguridad
    salt = secrets.token_hex(16)
    contrasena = entrada_texto.encode('utf-8') + salt.encode('utf-8')

    if algoritmo == "SHA-256":
        hashed_contrasena = hashlib.sha256(contrasena).hexdigest()
    elif algoritmo == "SHA-512":
        hashed_contrasena = hashlib.sha512(contrasena).hexdigest()
    else:
        # En caso de algoritmo no reconocido, usar SHA-256 por defecto
        hashed_contrasena = hashlib.sha256(contrasena).hexdigest()

    resultado_var.set(hashed_contrasena)
    actualizar_texto(hashed_contrasena, texto_resultado_contrasena)

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
etiqueta_generador = tk.Label(ventana, text="Generador de Contraseñas Encriptadas:")
etiqueta_generador.pack(pady=10)

boton_sha256 = tk.Button(ventana, text="Generar SHA-256", command=lambda: generar_contrasena_encriptada("SHA-256"))
boton_sha256.pack(pady=5)

boton_sha512 = tk.Button(ventana, text="Generar SHA-512", command=lambda: generar_contrasena_encriptada("SHA-512"))
boton_sha512.pack(pady=5)

# Crear Text para mostrar el resultado de las contraseñas encriptadas
texto_resultado_contrasena = tk.Text(ventana, height=3, width=40, state=tk.DISABLED)
texto_resultado_contrasena.pack(pady=10)


# Iniciar el bucle principal de la interfaz gráfica
ventana.mainloop()
