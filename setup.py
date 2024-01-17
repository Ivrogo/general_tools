from setuptools import setup, find_packages

setup(
    name='password-manager',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pymongo',  # Agrega tus dependencias aquí
        'tk',       # Añade cualquier dependencia adicional
    ],
    entry_points={
        'console_scripts': [
            'password-manager=password_manager:main',
        ],
    },
)