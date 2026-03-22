import socket
import sys, os, subprocess
import datetime
import json
import threading
from pathlib import Path

LOG_DIR = Path("honeypot_logs")
LOG_DIR.mkdir(exist_ok=True)

#On crée la classe de notre honeypot (possibilité d'en générer plusieurs qui fonctionneront de la meme manière sur des ip ou des ports différents)
class Honeypot :
    
    #Constructeur (on initialise l'ip, les ports a observé, les connexions et les fichiers de log)
    def __init__(self, ip="0.0.0.0", ports = [80, 8080]):
        self.ip = ip
        self.ports = ports
        self.connexion_active = {}
        self.log_file = LOG_DIR / f"honeypot{datetime.datetime.now().strftime('%d%m%Y')}.json"
        
    #Fonction pour enregistrer l'activité d'un utilisateur
    def log_activity(self, port, remote_ip, data):
        activity = {
            "timestamp" : datetime.datetime.now().isoformat(),
            "data" : data.decode('utf-8', errors='ignore'),
            "port" : port,
            "ip_distante" : remote_ip
        }
        
        #On récupère le fichier de log
        with open(self.log_file, 'a') as file:
            print("here")
            json.dump(activity, file)
            file.write('\n')
            
    #Gestion des connexions et simulation des services
    def gestion_connexion(self, ip_distante, port, socket_client):
        connex_bannieres = {
            21: "220 FTP server ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            7655: "Test OK"
        }
        
        try :
            #On regarde si le client s'est mis sur un des ports qu'on émule
            if port in connex_bannieres :
                #On lui envoie la bannière correspondate en binaire
                socket_client.send(connex_bannieres[port].encode())
                
            #A l'infini
            while True:
                #On récupère la communication avec le client
                data = socket_client.recv(1024)
                if not data:
                    break
                
                #On log l'activité du client
                self.log_activity(port, ip_distante, data)
                
                if port == 80:
                    chaine = self.action_shell(data, socket_client)
                    socket_client.send(chaine)
                else : 
                    #On simule une réponse
                    socket_client.send(b"Command not recognized.\r\n")

        except Exception as e:
            print(f"Error connection{e}")
                
        finally: 
            socket_client.close()
            
    
    def ecouteur(self, port):
        try:
        #On ne gère que les connexions IPV4 avec TCP
            serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #On definit IP + Port
            serveur.bind((self.ip, port))
            #Seulement 5 tentatives de connexion non autorisé
            serveur.listen(5)
            print(f"On écoute sur {self.ip} au port: {port} ")
            
            while True:
                client, addr = serveur.accept()
                print(f"Connexion en provenance de : {addr[0]}:{addr[1]}")
                
                #On gère les clients sur des Threads différents
                gestion_client = threading.Thread(
                    target=self.gestion_connexion,
                    args=(addr[0], port, client)
                )
                gestion_client.start()
                
        except Exception as e : 
            print(f"Error starting listener on port {port}: {e}")
            
            
        def action_shell(self, data, socket_client):
            data = data.decode('utf-8', errors='ignore')
            if data.startswith("pwd") or data.startswith("ls"): 
                resultat = subprocess.run(['pwd'], capture_output=True, text=True)
                x = resultat.stdout.strip()
                print(x)
                return b"Va te faire"
            else : 
                return b"Non reconnue"