# Utiliser une image de base officielle Node.js comme runtime
FROM node:20

# Définir un répertoire de travail à l'intérieur du conteneur
WORKDIR /usr/src/app

# Installer les dépendances nécessaires
RUN apt-get update && \
    apt-get install -y build-essential libssl-dev libdbd-pg-perl postgresql-client && \
    curl -L https://cpanmin.us | perl - App::cpanminus && \
    cpanm --quiet --notest App::Sqitch

# Copier le package.json et le package-lock.json dans le répertoire de travail courant du conteneur
COPY package*.json ./

# Installer les dépendances de l'application
RUN npm install

# Copier le code de l'application dans le conteneur
COPY . .

# Exposer le port spécifié dans l'app au reste du monde
EXPOSE 4000

# Définir la commande qui sera exécutée automatiquement à l'instanciation d'un conteneur ==> démarrer mon serveur Node
CMD ["npm", "start"]
