/**
 * Updates a user object in the users array based on the provided id.
 *
 * @param {type} id - The id of the user to update.
 * @param {type} user - The user object with updated information.
 * @return {type} undefined
 */
const users = [];
const messages = [];

export default (io) => {
  io.on('connection', (socket) => {
    const user = {
      id: socket.id,
      ip: socket.handshake.address,
      username: socket.id,
    };

    socket.on('connecting', (firstname) => {
      user.username = firstname;
    });

    users.push(user);

    // L'événement pour rejoindre le projet
    socket.on('joinProject', (projectData) => {
      if (user.project) {
        console.log(`The user ${user.username} left project ${user.project.name} id ${user.project.id}`);
        socket.leave(user.project.id);
      }
      user.project = projectData;
      socket.join(user.project.id);
      io.to(user.project.id).emit('userState', user);
      io.to(user.project.id).emit('chatState', { users, messages });
      console.log(`The user  ${user.username} joined project ${user.project.name}`);
    });

    // L'événement pour quitter le projet
    socket.on('leaveProject', (projectId) => {
      io.to(user.project.id).emit('chatState', { users, messages });
      socket.leave(projectId);
      console.log(`Socket ${socket.id} left project ${projectId}`);
    });
    socket.on('newCollaborator', () => {
      io.to(user.project.id).emit('refreshCollaborators');
    });
    socket.on('boardEvent', () => {
      io.to(user.project.id).emit('refreshBoard');
    });

    // L'événement pour envoyer un message au projet
    socket.on('messageCreation', () => {
      io.to(user.project.id).emit('receiveMessage');
    });

    socket.on('disconnect', () => {
      const userIndex = users.findIndex(
        (currentUser) => currentUser.id === user.id,
      );
      if (userIndex !== -1) {
        users.splice(userIndex, 1);
      }
      // io.to(user.project.id).emit('chatState', { users, messages });
    });
  });
};
