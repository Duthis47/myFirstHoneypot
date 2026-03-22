from Honeypot import Honeypot 
import time, sys, threading

def main():
    honeypot = Honeypot()
    for port in honeypot.ports : 
        thread_ecoute = threading.Thread(
            target=honeypot.ecouteur,
            args=(port,)
        )
        thread_ecoute.daemon = True
        thread_ecoute.start()
        
    try:
        #On n'arrete pas le programme
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
        sys.exit(0)
  
#Lance le programme      
if __name__ == "__main__":
    main()