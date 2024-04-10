#!/usr/bin/python

try:
    import logging
    import sys
    import os
    import time
    import requests
    import json
    from flask_cors import CORS
    from flask_wtf.csrf import CSRFProtect
    from flask_httpauth import HTTPBasicAuth
    from flask_login import LoginManager, UserMixin, current_user, login_required, login_user
    from flask import Flask, render_template, abort, make_response, request, redirect, jsonify, send_from_directory
    from utilwaza import UtilWaza

except ImportError:

    logging.error(ImportError)
    print((os.linesep * 2).join(['[http-server] Error al buscar los modulos:',
                                 str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)

############################# Configuraci'on de Registro de Log  ################################
FORMAT = '%(asctime)s %(levelname)s : %(message)s'
root = logging.getLogger()
root.setLevel(logging.INFO)
formatter = logging.Formatter(FORMAT)
# Log en pantalla
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
#fh = logging.FileHandler('logger.log')
#fh.setLevel(logging.INFO)
#fh.setFormatter(formatter)
# se meten ambas configuraciones
root.addHandler(handler)
#root.addHandler(fh)

logger = logging.getLogger('HTTP')
# ===============================================================================
# Configuraciones generales del servidor Web
# ===============================================================================

SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY','NO_SECRET_KEY')
SECRET_CSRF = os.environ.get('SECRET_KEY_CSRF','KEY-CSRF-ACA-DEBE-IR')
LOGIA_API_KEY = os.environ.get('LOGIA_API_KEY','None')

app = Flask(__name__)
app.config.update( DEBUG=False, SECRET_KEY = str(SECRET_CSRF), )

#login_manager = LoginManager()
#login_manager.init_app(app)

csrf = CSRFProtect()
csrf.init_app(app)

auth = HTTPBasicAuth()
# cors = CORS(app, resources={r"/page/*": {"origins": ["*"]}})
cors = CORS(app, resources={r"/page/*": {"origins": ["dev.jonnattan.com"]}})
# ===============================================================================
# variables globales
# ===============================================================================
ROOT_DIR = os.path.dirname(__file__)

#===============================================================================
# Redirige
#===============================================================================
@app.route('/', methods=['GET', 'POST'])
@csrf.exempt
def index():
    logging.info("Reciv solicitude endpoint: /" )
    return redirect('/info'), 302

#===============================================================================
# Redirige
#===============================================================================
@app.route('/<path:subpath>', methods=('GET', 'POST'))
@csrf.exempt
def processOtherContext( subpath ):
    logging.info("Reciv solicitude endpoint: " + subpath )
    return redirect('/info'), 302

#===============================================================================
# Redirige a base
#===============================================================================
@app.route('/info', methods=['GET', 'POST'])
@csrf.exempt
def infoJonnaProccess():
    logging.info("Reciv solicitude endpoint: /info" )
    return jsonify({
        "Servidor": "dev.jonnattan.com",
        "Nombre": "API Whatsapp",
    })

# ==============================================================================
# Waza
# ==============================================================================
@app.route('/page/waza/<path:subpath>', methods=['POST'])
@auth.login_required
@csrf.exempt
def waza( subpath ):
    waza = UtilWaza( ROOT_DIR )
    msg, code = waza.requestProcess(request, subpath)
    del waza
    return msg, code

# ==============================================================================
# Hook desde la API de Waza, no posee firma de nada y por lo tanto sin seguridad
# ==============================================================================
@app.route('/waza', methods=['POST','GET','PUT'])
@csrf.exempt
def wazasp( ):
    waza = UtilWaza( ROOT_DIR )
    msg, code = waza.requestProcess(request, None)
    del waza
    return msg, code

# ===============================================================================
# Metodo Principal que levanta el servidor
# ===============================================================================
if __name__ == "__main__":
    listenPort = 8085
    logger.info("ROOT_DIR: " + ROOT_DIR)
    logger.info("ROOT_DIR: " + app.root_path)
    if(len(sys.argv) == 1):
        logger.error("Se requiere el puerto como parametro")
        exit(0)
    try:
        logger.info("Server listen at: " + sys.argv[1])
        listenPort = int(sys.argv[1])
        # app.run(ssl_context='adhoc', host='0.0.0.0', port=listenPort, debug=True)
        # app.run( ssl_context=('cert_jonnattan.pem', 'key_jonnattan.pem'), host='0.0.0.0', port=listenPort, debug=True)
        app.run( host='0.0.0.0', port=listenPort)
    except Exception as e:
        print("ERROR MAIN:", e)

    logging.info("PROGRAM FINISH")
