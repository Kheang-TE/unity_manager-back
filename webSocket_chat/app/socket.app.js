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
  io.on("connection", (socket) => {
    const user = {
      id: socket.id,
      ip: socket.handshake.address,
      username: socket.id,
    };

    users.push(user);

    socket.emit("userState", user);

    io.emit("chatState", { users, messages });

    socket.on("send", async (message) => {
      if (message === "loaded") {
        let response = "Server is loaded";
        const serverMessage = {
          user: {
            username: user.username,
            server: true,
          },
          message: response,
        };
        messages.push(serverMessage);
        socket.emit("message", serverMessage);
      } else {
        const userMessage = { user, message };
        messages.push(userMessage);
        socket.broadcast.emit("message", userMessage);
      }
    });

    socket.on("disconnect", () => {
      const userIndex = users.findIndex(
        (currentUser) => currentUser.id === user.id
      );
      if (userIndex !== -1) {
        users.splice(userIndex, 1);
      }

      io.emit("chatState", { users, messages });
    });
  });
};
