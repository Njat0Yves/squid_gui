# Structure `/etc/squid` pour ce projet

## 📁 Arborescence complète

/etc/squid/
├── squid.conf # Configuration principale de Squid
├── passwords # Fichier htpasswd des utilisateurs (géré par la GUI)
├── blocklist_global.txt # Liste des domaines bloqués pour tous
└── users_rules/ # Dossier contenant les règles par utilisateur
├── empty.conf # Fichier vide (nécessaire pour éviter l'erreur FATAL)

## ✅ Points clés

- **`passwords`** : Modifié par la commande `htpasswd` quand vous ajoutez un utilisateur.
- **`blocklist_global.txt`** : Édité directement par le script Python (onglet "Global").
- **`users_rules/*.txt`** : Liste des domaines bloqués par user (onglet "Par utilisateur").
- **`users_rules/*.conf`** : Généré automatiquement par le script à partir du `.txt` correspondant.
- **`empty.conf`** : Fichier factice pour éviter l'erreur `FATAL: Unable to find configuration file` si aucun utilisateur n'a de règle.
