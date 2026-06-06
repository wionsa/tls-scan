from setuptools import setup, find_packages

setup(
    name='certverifier',
    version='1.0.0',
    description='ML-IDS Engine: AI-powered SSL/TLS certificate security analysis',
    author='Botvynko Krystyna (tina.wionsa@gmail.com)',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.10',
    install_requires=[
        'setuptools',
        'cryptography',
        'pyOpenSSL',
        'pandas',
        'numpy',
        'scikit-learn',
        'requests',
        'beautifulsoup4',
        'colorama',
        'scapy',
        'flask',
        'flask-socketio',
        'werkzeug',
        'python-dotenv',
        'eventlet',
        'idna',
    ],
    entry_points={
        'console_scripts': [
            'cert-verifier=cert_verifier:main',
        ]
    },
)
