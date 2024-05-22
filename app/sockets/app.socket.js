/**
 * Updates a user object in the users array based on the provided id.
 *
 * @param {type} id - The id of the user to update.
 * @param {type} user - The user object with updated information.
 * @return {type} undefined
 */
const users = [];
let messages = [];

export default (io) => {
  io.on('connection', (socket) => {
    const user = {
      id: socket.id,
      ip: socket.handshake.address,
      username: socket.id,
    };

    users.push(user);

    socket.on('connecting', (firstname) => {
      user.username = firstname;
    });

    // L'événement pour rejoindre le projet
    socket.on('joinProject', (projectData) => {
      if (user.project) {
        console.log(`The user ${user.username} left project ${user.project.name}`);
        socket.leave(user.project);
      }
      user.project = projectData;
      socket.join(user.project);
      console.log(`The user  ${user.username} joined project ${user.project.name}`);
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

    socket.emit('userState', user);
    io.emit('chatState', { users, messages });

    socket.on('send', async (message) => {
      if (message === 'loaded') {
        const response = 'Server is loaded';
        const serverMessage = {
          user: {
            username: user.username,
            server: true,
          },
          message: response,
        };
        messages.push(serverMessage);
        io.emit('message', serverMessage);
      } else {
        const userMessage = { user, message };
        messages.push(userMessage);
        io.emit('message', userMessage);
      }
    });

    socket.on('clearMessages', () => {
      messages = [];
      io.emit('chatState', { users, messages });
    });

    socket.on('disconnect', () => {
      const userIndex = users.findIndex(
        (currentUser) => currentUser.id === user.id,
      );
      if (userIndex !== -1) {
        users.splice(userIndex, 1);
      }

      io.emit('chatState', { users, messages });
    });
  });
};
