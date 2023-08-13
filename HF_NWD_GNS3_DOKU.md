# HF_NWD_GNS3


## Ausgangslage


### 1 Einleitung

Sie haben als Netzwerkingenieur den Auftrag erhalten in einem KMU einen zusätzlichen Geschäftsstandort per VPN zu erschliessen. Das KMU hat keinen eigenen Betriebsinformatiker. Jedes Mal, wenn eine Erweiterung des Netzwerkes benötigt wurde, hat das KMU eine andere IT-Firma beauftrag. Das hat zur Folge, dass überall unterschiedliche Geräte und VPN-Technologien eingesetzt wurden. Das ist eine optimale Gelegenheit, um neue VPN-Technologien kennenzulernen und zu vergleichen! Die Wahl des Gerätes für Lausanne steht Ihnen frei. Alle anderen Standorte haben einen funktionierenden Internetanschluss und eine funktionierende VPN-Verbindung an den Hauptstandort in Zürich. In der Mitte finden Sie ein Netzwerk eines fiktiven ISP. Der verwendet OSPF als internes Routing-Protokoll (iBGP eignet sich für ISP besser). Über den ISP können sie auch auf das Internet zugreifen. 

Lernziele:

- Unterschiedliche VPN-Technologien kennenlernen
-	VPN auf einem Router konfigurieren, testen und dokumentieren Die messbaren Ziele sind direkt im GNS3 Projekt zu finden (siehe Screenshot oben)


### 2 Themengebite
Diese Laborübung beinhaltet folgende Themengebiete:

-	Kernthema: VPN Technologien OpenVPN, Wireguard, IPsec
-	IP-Protokolle, namentlich IPv4 und IPv6
-	Standardprotokolle wie HTTP, DHCP, DNS, ARP, ICMP, usw.
-	Bedienung bzw. Konfiguration und Steuerung von Netzwerkgeräten und Server über die CLI
-	Betriebssysteme: Cisco IOS, MikroTik RouterOS, pfsense
-	Netzwerkdokumentation
 
### 3 Allgemeine Instruktion
Bitte lesen Sie diese Instruktionen sorgfältig durch und fragen Sie bei Unklarheiten den Kursleiter. In diesem Modul arbeiten Sie mit der Netzwerksimulationssoftware GNS3, mit der Sie per Drag-and-Drop Topologien in Sekundenschnelle aufbauen können. Im Hintergrund arbeitet GNS3 mit Qemu-KVM VMs für die Switche und Router und verbindet diese bezüglich Ihrer Topologie mit Linux-Bridges. Weitere Informationen zum Aufbau der TBZ Cloud Infrastruktur finden Sie im Repository https://gitlab.com/ch-tbz-it/Stud/allgemein/tbzcloud-gns3 Sie arbeiten jeweils in Zweier-Teams am selben Labor auf demselben Server bzw. derselben TBZ Cloud GNS3 Instanz. Wie Sie eine Verbindung zu Ihrer Instanz aufbauen können, erfahren Sie unter https://gitlab.com/ch-tbzit/Stud/allgemein/bzcloud-gns3/-/tree/main/02_Bedienungsanleitung . Den OpenVPN Key zu Ihrer Instanz erhalten Sie vom Kursleiter. Damit Sie die Aufgaben lösen können, müssen Sie selbstständig im Internet recherchieren. Nicht alle notwendigen Informationen sind in diesem Dokument vorhanden. Folgende Zugangsdaten sind bekannt:

-	MikroTik: Benutzername: admin, Passwort: tbz1234
-	Debian: Benutzername: debian, Passwort: debian
-	Cisco: Passwort: tbz1234
-	Standardpasswörter zum Ausprobieren: cisco, debian, admin1234, admin

### 4 Aufgaben
#### 4.1 VPN Technologien per Packet Capture analysieren
Die drei verwendeten VPN-Technologien bauen auf unterschiedlichen Netzwerkstacks auf. Analysieren Sie die unterschiedlichen Protokolle mithilfe von Wireshark Captures und halten Sie Unterschiede in den Netzwerkstacks fest. Beantworten Sie mithilfe der Packet Caputes zusätzlich folgende Fragen in Ihrem Bericht: Weshalb kann IPSec und NAT ein Problem darstellen?
#### 4.2 Neuen Standort Anbinden
1.	Lesen Sie die Anforderungen an das Netzwerk und das Ziel. Entscheiden Sie sich für einen Router-Typ und richten das Gerät ein.
2.	Richten Sie den Zugriff für Worker1 ein. Worker1 hat bereits via OpenVPN und Wireguard Zugriff auf zwei Standorte.
3.	Testen und Konfigurieren Sie so lange bis alle Anforderungen erfüllt sind.
4.	Dokumentieren Sie alle getätigten Konfigurationen so, dass eine andere Fachperson Ihre Konfiguration möglichst schnell nachbauen kann und versteht, was sie dabei tut (Dazu gehört unter anderen auch, dass sie z.B. alle Befehle per Copy-Paste einfügen kann)
Wenn Sie den Bericht abgeben, muss ihr Netzwerk in einem funktionsfähigen Zustand sein. Der Kursleiter wird nebst dem Bericht auch ihr GNS3 Labor überprüfen.
### 5 Hinweise zur Dokumentation
-	Beschränken Sie sich auf das Wesentliche. Unterlassen Sie es leere Sätze oder persönliche Statements zu schreiben. Fokussieren Sie sich auf die Sachlage.
-	Nachvollziehbarkeit: Anhand ihrer Dokumentation müssen Dritte in der Lage sein, alles exakt genau gleich nachbauen zu können.
-	Erstellen Sie pro Gruppe ein eigenes privates Repository mit dem Namen HF_NWD und pushen Sie dieses auf GitLab (Alternativ GitHub). Gewähren Sie der Lehrperson den Zugriff auf das Repository.
-	Machen Sie bei der Abgabe einen Export des aktuellen Repository-Standes und geben diesen als ZIP-File via Teams-Aufgabe ab.
-	Die gesamte Dokumentation muss in Markdown erfolgen. Fügen Sie erstellte Netzwerktopologien als Grafiken ein.
-	Alle Grafiken sind scharf und müssen gut zu lesen sein.
-	Als Inspiration können Sie die Vorlagen von diesem Repository verwenden: https://gitlab.com/alptbz/beispiellernjournal-fuer-laboruebungen. Lassen Sie die Reflexion und das aufführen ihrer neuen Lerninhalte weg.
### 6 Regeln
-	Es dürfen keine Geräte entfernt oder hinzugefügt werden – ausser am Standort Lausanne.
-	Es ist erlaubt zu Testzwecken z.B. ein Ubuntu Desktop an einem Port anzuschliessen – wie wenn Sie ein Laptop an einem «echten» Router oder Switch einstecken.
-	Alle Kabelverbindungen zwischen den Geräten sind fix. Erstellen Sie keine neuen (Ausser die für Lausanne – siehe Hinweis im GNS3 Projekt).

### 7 Bewertungskriterien und Abgabetermin
Informieren Sie sich bei der Kursleitung betreffend Abgabetermin und Bewertungskriterien. Zu spät abgegebene (bis 24h) Arbeiten erhalten Abzug nach Ermessen der Kursleitung. 24 Stunden nach dem Abgabetermin werden keine Arbeiten akzeptiert und die Aufgabe gilt als nicht erfüllt.

 ### 8 Links
 - <a href="[de.wikipedia.org/wiki/Protokollstape]">Protokollstapel</a>
 - <a href="[mikrotik.com/]">Mikrotik</a>
 - <a href="[help.mikrotik.com/docs/display/ROS/RouterOS]">RouterOS</a>
 - <a href="[www.wireguard.com]">Wireguard</a>
 - <a href="[www.cisco.com/c/en/us/td/docs/net_mgmt/vpn_solutions_center/2-0/ip_security/provisioning/guide/IPsecPG1.html]">Cisco IPsec Introduction</a>
 -  <a href="[blog.ipfire.org/post/why-not-wireguard]">Blogeintrag über Wireguard</a>

# Doku

## Aufbau Lausanne :
 
 AUF GNS3  im Firmenstandort Lausanne wird zunächst ein Router und ein Debian System aufgebaut

![Bild1](/Bilder/1.PNG)

Dannach erfolgt die Konfiguration von Lausanne:

Router Lausanne

Zunächst den Namen geändert

> /system/identity/set name=LS-R1

![Bild2](/Bilder/Bild46.PNG)



Dannach Ether1 und Ether2 definiert: 

> /ip/address/add address=203.0.113.70/30 interface=ether1 network=203.0.113.69

> /ip/address/add address=192.168.13.1/24 interface=ether2 network=192.168.13.0

 ![Bild3](/Bilder/Bild2.png)
 

Nun muss auch das routing konfiguert werden werden.

> /ip/route/add dst-address=0.0.0.0/0 gateway=203.0.113.69

![Bild3](/Bilder/Bild3.png)
 

Damit nun der Router externe DNS anfragen bearbeiten kann, muss auch die Funktion "allow-remote-requests" konfiguriert werden

> /ip/dns/set/allow-remote-requests=yes servers=8.8.8.8

![Bild3](/Bilder/Bild4.png)



Dannach wird DHCP konfiguriert

> /ip/dhcp-server/network add address=192.168.13.0/24 dns-server=192.168.13.1 gateway=192.168.13.1

![Bild3](/Bilder/Bild5.png)


und der Range für DHCP gesetzt

> /ip/pool/add name=dhcp_pool1 ranges=192.168.13.50-192.168.13.100

![Bild3](/Bilder/Bild6.png)


nun muss für den erstellten Pool auch ein Ether definiert werden, den wir auch benennen

> /ip/dhcp-server/add address-pool=dhcp_pool1 interface=ether2 name=dhcp1

![Bild3](/Bilder/Bild7.png)



Mit dieser Regel, wird der ausgehende Datenverkehr, der das Interface "ether1" verlässt, getarnt, indem die Quell-IP-Adresse des Datenverkehrs durch die IP-Adresse des Routers ersetzt wird. Dadurch wird der ausgehende Datenverkehr für externe Systeme so aussehen, als käme er vom Router selbst. "Scrnat" ist die Quell-NAT gemeint, die für den ausgehenden Datenverkehr zuständig ist (der über ether1 führt)

>/ip/firewall/nat add action=masquerade chain=srcnat out-interface=ether1


![Bild3](/Bilder/Bild8.png)



 

### Aufbau IPsec: Site-To-Site / Basel <=> Lausanne

#### Konfiguration Router Lausanne 

Nun muss ein IPsec-Profil erstellt werden, das die Sicherheitsparameter für den Schlüsselaustausch und die Verschlüsselung festlegt. Es verwendet die Diffie-Hellman-Gruppe "modp2048" für den Schlüsselaustausch und den AES-128-Verschlüsselungsalgorithmus für die verschlüsselte Kommunikation.

> /ip/ipsec/profile add dh-group=modp2048 enc-algorithm=aes-128 name=ike1-BS

![Bild3](/Bilder/Bild10.png)


Um die Art der Verschlüsselung, Authentifizierung und Schlüsselaustausch zu bestimmen, machen wir mit "proposel" einen Vorschlag wie dieser geschehen soll: 

> /ip/ipsec/proposal add enc-algorithms=aes-128-cbc name=ike1-BS pfs-group=modp2048

 ![Bild3](/Bilder/Bild11.png)

für eine ipSEC verbindung muss nun auch die andere Seite, wohin der Tunnel führen soll, bestimmt werden. Dazu wird hier ein neuer IPsec-Peer mit dem Namen "ike1-BS" hinzugefügt, der die IP-Adresse 203.0.113.82 hat. Dieser Peer wird das zuvor definierte IPsec-Profil "ike1-BS" verwenden, um eine sichere Verbindung mit diesem Remote-Partner herzustellen.

> /ip/ipsec/peer add address=203.0.113.82/32 name=ike1-BS profile=ike1-BS

 ![Bild3](/Bilder/Bild12.png)


Für die Kommunikation mit ipSEC brauchen wir nun auch eine Idnetität mit der wir kommunizieren können, der wir einen Passwort zur authentifizierung setzen
 

> /ip/ipsec/identity add peer=ike1-BS secret=tbz1234

 ![Bild3](/Bilder/Bild13.png)



Nun muss auch eine IPsec-Richtlinie erstellt werde, um den Datenverkehr zwischen der Quell und dem Ziel über den IPsec-Tunnel zu schützen. Dies erfolgt durch die Erstellung eines verschlüsselten Tunnels zwischen den angegebenen Netzwerken.

 > /ip/ipsec/policy add dst-address=192.168.11.0/24 peer=ike1-BS proposal=ike1-BS src-address=192.168.13.0/24 tunnel=yes

![Bild3](/Bilder/Bild14.png)


Wir haben unten die Problematik von IPSec und NAT erklärt, dieser wir nun entgegenwirken müssen, indem wir eine Sonderregel setzen: 


>/ip/firewall/filter add chain=forward action=accept src-address=192.168.11.0/24 dst-address=192.168.13.0/24 connection-state=established,related

>/ip/firewall/filter add chain=forward action=accept src-address=192.168.13.0/24 dst-address=192.168.11.0/24 connection-state=established,related
 
![Bild3](/Bilder/Bild16.png)



### Konfiguration Router Basel 

das gleiche nun für Basel

> /ip/ipsec/profile  add dh-group=modp2048 enc-algorithm=aes-128 name=ike1-LS

![Bild3](/Bilder/Bild18.png)
 
> /ip/ipsec/proposal add enc-algorithms=aes-128-cbc name=ike1-LS pfs-group=modp2048


 ![Bild3](/Bilder/Bild19.png)


> /ip/ipsec/peer add address=203.0.113.70/32 name=ike1-LS profile=ike1-LS

 ![Bild3](/Bilder/Bild20.png)

> /ip/ipsec/identity add peer=ike1-LS

  ![Bild3](/Bilder/Bild21.png)

> /ip/ipsec/policy add dst-address=192.168.13.0/24 peer=ike1-LS proposal=ike1-LS src-address=192.168.11.0/24 tunnel=yes

  ![Bild3](/Bilder/Bild22.png)


> /ip/firewall/nat add action=accept chain=srcnat dst-address=192.168.13.0/24 src-address=192.168.11.0/24

![Bild3](/Bilder/Bild23.png)

> /ip/firewall/filter add chain=forward action=accept src-address=192.168.11.0/24 dst-address=192.168.13.0/24 connection-state=established,related

> /ip/firewall/filter add chain=forward action=accept src-address=192.168.13.0/24 dst-address=192.168.11.0/24 connection-state=established,related

![Bild3](/Bilder/Bild47.PNG)



Sobald der Wireguard (unterhalb) aufgebaut wurde, wurde der IPSec Tunnel kontrolliert, indem wir über den Worker1 auf die Weboberfläche des Lausane und Basel Router mittels der IP zugriffen:  

![Bild3](/Bilder/Bild25.png)

![Bild3](/Bilder/Bild26.png)



### Aufbau VPN WireGuard: Site-To-Site / Zürich <=> Lausanne

Nun muss der VPN WireGuard eingerichtet werden, dazu müssen auf beide Seiten Schnittstelen konfiguriert werden. Diese Schnittstelle werden den eingehenden Datenverkehr über einen zu bestimmenden Port empfangen der für sichere Netzwerkkommunikation genutzt wird.

#### Router Lausanne

> /interface/wireguard add listen-port=13234 name=wireguardZH
 
![Bild3](/Bilder/Bild27.png)

 
Nun müssen wir den Partner (Peer) definieren. Für die Verschlüsselung und Authentifizierung für die Kommunikation zwischen den Peers geben wir den Public-key von Zürich mit

> /interface/wireguard/peers add allowed-address=192.168.9.0/24 endpoint-address=203.0.113.98 endpoint-port=13234 interface=wireguardZH \public-key="yWwRYBChRvZOTiBdGKaxaq5+R9eFslvoMIHdDOljGiE="

![Bild3](/Bilder/Bild48.PNG)

auch ein neues routing muss nun configuriert werden

> /ip/address add address=192.168.250.1/30 interface=wireguardZH

> /ip/route add dst-address=192.168.9.0/24 gateway=wireguardZH

![Bild3](/Bilder/Bild49.PNG)

Nun müssen wir die Forward und Input Regel für die Firewall-Filter setzen

> /ip/firewall/filter add action=accept chain=input dst-port=13234 protocol=udp src-address=203.0.113.98
> /ip/firewall/filter add action=accept chain=input dst-port=13234 protocol=udp src-address=192.168.250.2
> /ip/firewall/filter add action=accept chain=forward dst-address=192.168.9.0/24 src-address=192.168.13.0/24
> /ip/firewall/filter add action=accept chain=forward dst-address=192.168.13.0/24 src-address=192.168.9.0/24

![Bild3](/Bilder/Bild50.PNG)


#### Router Zürich 

nun das gleiche beim Router Zürich

> /interface/wireguard> add listen-port=13234 name=wireguardLS
 
> /interface/wireguard/peers add allowed-address=192.168.13.0/24 endpoint-address=203.0.113.70 endpoint-port=13234 interface=wireguardLS \ public-key="lZexpEtJY2Pdb4X0oC7D63iOTMZqziYirHybnePaXkg="

> /ip/address add address=192.168.250.1/30 interface=wireguardLS

> /ip/route add dst-address=192.168.9.0/24 gateway=wireguardZH

> /ip/firewall/filter add action=accept chain=input dst-port=13234 protocol=udp src-address=203.0.113.70
> /ip/firewall/filter add action=accept chain=input dst-port=13234 protocol=udp src-address=192.168.250.1
> /ip/firewall/filter add action=accept chain=forward dst-address=192.168.13.0/24 src-address=192.168.9.0/24
> /ip/firewall/filter add action=accept chain=forward dst-address=192.168.9.0/24 src-address=192.168.13.0/24
 


### Aufbau VPN Roadwarior: PC-to-PC  / Worker1 <=> Debian

Nachdem wir eine Netzwerk zu Netzwerk Tunnel mit Wireguard aufgebaut haben, bauen wir nun einen PC zu PC Tunnelk mit dem VPN Roadwarrior auf, dazu konfigurieren wir den Wireguard Interface

beim Router Lausanne wird nun eine WireGuard-Schnittstelle erstellt, die auf Port 13233 mit einer maximalen Datengrösse von 1420 Bytes lauscht. Der Schnittstelle wird die IP-Adresse von Worker1 192.168.14.1/24 im Zürich Netzwerk 192.168.14.0/24 zugeordnet.

> /interface/wireguard add listen-port=13233 mtu=1420 name=MTW_LS
> /ip/address add address=192.168.14.1/24 interface=MTW_LS network=192.168.14.0


![Bild3](/Bilder/Bild51.PNG)


Nun wird ein neuer WireGuard-Peer erstellt und der WireGuard-Schnittstelle "MTW_LS" hinzugefügt

> /interface/wireguard/peers add allowed-address=192.168.14.2/32 interface=MTW_LS public-key=\
"9nSj/xiApoAJrZX99+EwJuiDH5Xp5WZrD2ceCecGrgc="

![Bild3](/Bilder/Bild55.PNG)

wie oben, muss auch hier eine Firewall-Regel eigepflegt werden um einer Blockade entgegenzuwirken

> /ip/firewall/filter add chain=forward action=accept src-address=192.168.13.0/24 dst-address=192.168.11.0/24 connection-state=established,related
 

![Bild3](/Bilder/Bild52.PNG)

Nun erstellen wir eine Regel die den Datenverkehr über WireGuard erlaubt, indem es den Datenverkehr in der "input"-Kette der Firewall akzeptiert. 
 
/ip/firewall/filter add action=accept chain=input comment="allow WireGuard traffic" src-address=192.168.14.0/24

 ![Bild3](/Bilder/Bild53.PNG)


### Zugriff auf File-Share

Damit Worker1 aus dem Internetcafe Zugriff auf Dateien das Debian-System von Lausanne bekommt, muss zunächst der Debian-System vorberietet werden, indem wir einen einen Samba File-Share Server installieren

zunächst muss ein Superuser samt Passwort erstellt werden

> sudo useradd worker

> sudo passwd worker1 
> tbz1234

Dannach installieren wie den File-Server

aber zunächst noch der paket-manager updatet

> sudo apt -get update

dannach installieren

> sudo apt-get install samba

dannach erstellen wir für den Samba FileShare einen User

> sudo smbpasswd -a worker
> tbz1234

damit der user Zugriff bekommt, wechslen wir ihn zu Root User

> sudo -s

und erstellen einen Ordner

> mkdir /home/worker/shared_folder

und passen die Berechtigung und wer darauf berechtigt ist ein

> chown worker1 shared_folder
> chgrp worker1 shared_folder

nun das Konfig von samba öffnen

> sudo nano /etc/samba/smb.conf

und folgende Konfig zu unterst einfügen und speichern

> [shared_folder]
path = /home/worker/shared_folder
readonly = no
inherit permisson = yes

und restarten Samba

> service smbd restart

### Test Fileshare

Um nun den Zugriff auf den Fileshare in Laussanne zu testen, woird auif dem Worker1 im Internet Cafe das Laufwerk des Debian-System über die IP den zuvor erstellten Ordner gemapt: \\192.168.13.100\shared_folder

für den Login verwenden wir den User den wir auf den Debian-System zuvor erstellten haben mit der IP des Debian System als Domäne: 
- Benutzername: worker
- PW: tbz1234


![Bild3](/Bilder/Bild56.png)



 # Weshalb kann IPSec und NAT ein Problem darstellen

IPsec (Internet Protocol Security) ist eine Technologie, die verwendet wird, um die Sicherheit von Datenübertragungen über das Internet zu gewährleisten. Sie erstellt einen verschlüsselten Tunnel für den Datenverkehr, um sicherzustellen, dass die Informationen sicher übertragen werden und niemand außer den beteiligten Parteien darauf zugreifen kann.

NAT (Network Address Translation) ist eine Methode, mit der Netzwerkgeräte private IP-Adressen in öffentliche IP-Adressen übersetzen, wenn sie mit dem Internet kommunizieren. Das ermöglicht mehreren Geräten im privaten Netzwerk, die gleiche öffentliche IP-Adresse zu verwenden, um ins Internet zu gelangen.

Wenn man beides gleichzeitig einsetzt, kann es zu Problemen kommen:

Adresskonflikt: IPsec arbeitet mit bestimmten Adressen, um die Verschlüsselung durchzuführen. Wenn NAT die Adressen ändert, um den Datenverkehr ins Internet zu leiten, kann das zu Verwirrung führen. Die Adressen passen dann nicht mehr zusammen, und die Kommunikation kann gestört werden.

Verschlüsselungskollision: IPsec verschlüsselt die Daten für sichere Übertragung. Wenn NAT die Adressen ändert, kann es die Verschlüsselung durcheinanderbringen, da die Informationen nicht mehr mit den erwarteten Adressen übereinstimmen.

Komplexität: Beide Technologien erfordern spezifische Konfigurationen. Wenn du beides zusammen verwendest, erhöht sich die Komplexität der Konfiguration. Das kann zu Fehlern oder unerwartetem Verhalten führen.

Zusammenfassend kann die gleichzeitige Nutzung von IPsec und NAT dazu führen, dass die Datenübertragung nicht reibungslos funktioniert oder sogar Sicherheitsrisiken entstehen. Deshalb sollte man sorgfältig überlegen, ob beide Technologien wirklich notwendig sind und wie sie zusammenarbeiten können, um Probleme zu vermeiden.










