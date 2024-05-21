/*
Afin d'émettre depuis le serveur des informations à différentes cibles on à 3 possiblités :
  - On veut parler a l'utilisateur courant (socket) : socket.emit
  - On veut parler à tous les utilisateurs autres que l'utilisateur courant : socket.broadcast.emit
  - On veut parler à TOUS les utilisateurs : io.emit
*/

export default (io) => {
  io.on('connection', (socket) => {
    // L'événement pour rejoindre le projet
    socket.on('joinProject', (projectId) => {
      socket.join(projectId);
      console.log(`Socket ${socket.id} joined project ${projectId}`);
    });

    // L'événement pour quitter le projet
    socket.on('leaveProject', (projectId) => {
      socket.leave(projectId);
      console.log(`Socket ${socket.id} left project ${projectId}`);
    });

    // L'événement pour envoyer un message au projet
    socket.on('sendMessage', (message) => {
      io.to(message.project_id).emit('receiveMessage', message);
    });

    socket.on('disconnect', () => {
      console.log(`Socket ${socket.id} disconnected`);
    });
  });
};
