# bettercap-wifi — app Flutter

Petite application Flutter qui pilote le backend WiFi (`../`) via son **API HTTP**.

## Ce qu'elle fait

- **Handshakes (onglet principal)** : centrée sur les captures, alimentée par la route
  durable **`GET /api/handshakes`** (dérivée de l'état WiFi du backend, pas du flux
  d'événements) :
  - compteur global + répartition **PMKID / FULL / HALF**, et chemin du **fichier .pcap** de sauvegarde ;
  - une carte par capture : réseau (ESSID/BSSID), station cliente (+ vendor), type, canal,
    chiffrement, paquets non sauvés ;
  - actions directes **Assoc (PMKID)** / **Deauth** pour (re)forcer une capture ;
  - **Télécharger le .pcap** (`GET /api/handshakes/pcap`) : enregistre le fichier de captures
    dans le dossier personnel local ;
  - accumulation en mémoire (clé = AP+station, on garde le plus fort) : une capture reste
    listée pour la session même si son AP est purgé par TTL côté backend.

  > Côté backend, le serveur accumule aussi les handshakes depuis le bus d'événements,
  > pour que le détail (PMKID/half/full + station) survive à la purge TTL des stations.
- **Points d'accès** : liste live des APs (ESSID, BSSID, canal, RSSI coloré, chiffrement,
  nombre de clients, présence de handshake, WPS). Dépliage → clients associés + actions.
- **Actions** (envoyées comme commandes à `POST /api/session`) :
  - Toggle **Recon ON/OFF** (`wifi.recon on|off`)
  - Réglage des **canaux** / hopping (`wifi.recon.channel …`)
  - Par AP : **Deauth** (`wifi.deauth <bssid>`), **Assoc/PMKID** (`wifi.assoc <bssid>`), **WPS** (`wifi.show.wps`)
  - Par client : **Deauth** ciblé
- **Événements** : flux `/api/events` (nouveaux APs/clients, handshakes, deauths…), avec purge.
- **Console** : envoi de n'importe quelle commande `wifi.*` + raccourcis.
- **Réglages** : URL du backend + jeton API (`X-Api-Token`).

Aucune dépendance externe : le client HTTP utilise `dart:io` (sockets bruts).
Cibles : **desktop (macOS/Linux/Windows) et mobile**. Pas le web (`dart:io` non supporté).

## Lancer

1. Démarrer le backend (root requis pour la capture monitor) :
   ```bash
   cd ..
   sudo ./bettercap-wifi -iface wlan0 -api-address 127.0.0.1:8081
   # avec jeton : -api-token monsecret
   ```
2. Lancer l'app :
   ```bash
   flutter run -d macos      # ou: flutter run -d <device>
   ```
3. Dans l'app : ⚙️ → régler l'URL (`http://127.0.0.1:8081`) et le jeton si besoin.

> Depuis un mobile, mets l'IP de la machine qui fait tourner le backend
> (ex. `http://192.168.1.10:8081`) et démarre le backend avec
> `-api-address 0.0.0.0:8081`.

## Structure

- `lib/api_client.dart` — client HTTP + modèles (`AccessPoint`, `WifiClient`, `ApEvent`, `SessionInfo`).
- `lib/main.dart` — UI (Material 3 sombre) : barre de contrôle + onglets APs / Événements / Console.
