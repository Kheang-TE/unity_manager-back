# Unity Manager

## General Information
- **Project Name**: projet-gestionnaire-projet-back
- **Version**: 0.1.0
- **Private**: Yes
- **Type**: module
- **Description**: Unity Manager is a dynamic project management application featuring real-time collaboration tools, including an integrated chat system. It allows teams to efficiently manage tasks, track project progress, and communicate seamlessly within a single platform.
- **Author**: Kheang TE, Mohamed ZERROUKI, Xavier Landron, Henry Iosipov
- **License**: ISC

## Getting Started

### Prerequisites
Make sure you have the following installed:
Make sure you have the following installed:
- [Node.js](https://nodejs.org/) (v14 or higher)
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)
- [MongoDB](https://www.mongodb.com/)
- [PostgreSQL](https://www.postgresql.org/)
- [Sqitch](https://sqitch.org/)

### Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/your-username/projet-gestionnaire-projet-back.git
    ```
2. Navigate to the project directory:
    ```sh
    cd projet-gestionnaire-projet-back
    ```
3. Install the dependencies:
    ```sh
    npm install
    ```
    or
    ```sh
    yarn install
    ```

### Running the Project
To get the front-end project: [https://github.com/Kheang-TE/unity_manager-front](https://github.com/Kheang-TE/unity_manager-front)

To start the development server:
    ```sh
    npm run dev
    ```
    or
    ```sh
    yarn dev
    ```

To start the production server:
    ```sh
    npm run start
    ```
    or
    ```sh
    yarn start
    ```



## Project Structure
```
├── app
│   ├── controllers
│   │   ├── card.controller.js
│   │   ├── core.controller.js
│   │   ├── list.controller.js
│   │   ├── message.controller.js
│   │   ├── project.controller.js
│   │   ├── tag.controller.js
│   │   └── user.controller.js
│   ├── errors
│   │   └── api.error.js
│   ├── middlewares
│   │   ├── authentification.middleware.js
│   │   ├── bodySanitizer.middleware.js
│   │   ├── checkAccess.middleware.js
│   │   ├── controller.wrapper.js
│   │   ├── error.middleware.js
│   │   ├── rateLimiter.middleware.js
│   │   └── validation.middleware.js
│   ├── models
│   │   ├── associations.js
│   │   ├── Card.js
│   │   ├── index.js
│   │   ├── List.js
│   │   ├── Message.js
│   │   ├── mongooseClient.js
│   │   ├── Project.js
│   │   ├── sequelizeClient.js
│   │   ├── Tag.js
│   │   └── User.js
│   ├── routers
│   │   ├── card.router.js
│   │   ├── index.js
│   │   ├── list.router.js
│   │   ├── message.router.js
│   │   ├── project.router.js
│   │   ├── tag.router.js
│   │   └── user.router.js
│   ├── schemas
│   │   ├── card.create.schema.js
│   │   ├── card.update.schema.js
│   │   ├── list.create.schema.js
│   │   ├── list.update.schema.js
│   │   ├── message.create.schema.js
│   │   ├── message.update.schema.js
│   │   ├── project.create.schema.js
│   │   ├── project.update.schema.js
│   │   ├── tag.create.schema.js
│   │   ├── tag.update.schema.js
│   │   ├── user.create.schema.js
│   │   ├── user.signin.schema.js
│   │   └── user.update.schema.js
│   ├── sockets
│   │   └── app.socket.js
│   └── tests
│       ├── authentification.middleware.test.js
│       └── bodySanitizer.middleware.test.js
├── db
│   ├── migrations
│   │   ├── sqitch.conf
│   │   └── sqitch.plan
│   └── seeding
│       └── seed.sql
├── index.js
├── package.json
├── package-lock.json
└── README.md
```

## API Documentation

The API routes are documented using Swagger. You can access the Swagger documentation at the following URL after starting the server:

```
http://localhost:3000/api-docs
```
## Database Setup

### MongoDB

1. Make sure MongoDB is installed and running.
2. Configure the MongoDB connection in your `.env` file:
    ```
    MONGODB_URI=mongodb://localhost:27017/unitymanager
    ```

### PostgreSQL

1. Make sure PostgreSQL is installed and running.
2. Configure the PostgreSQL connection in your `.env` file:
    ```
    DATABASE_URL=postgres://user:password@localhost:5432/unitymanager
    ```
## Environment Variables

Create a `.env` file in the root of your project and configure the following variables:

```
PORT=3000
MONGODB_URI="mongodb://localhost:27017/name_of_database"
PG_URL="postgres://username:password@localhost:5432/name_of_database"
JWT_SECRET="jwt_secret"
FRONTEND_URL="http://localhost:port/"
```

## Dependencies

- **bcrypt**: ^5.1.1
- **cookie-parser**: ^1.4.6
- **cors**: ^2.8.5
- **dotenv**: ^16.4.5
- **email-validator**: ^2.0.4
- **express**: ^4.19.2
- **express-jsdoc-swagger**: ^1.8.0
- **express-rate-limit**: ^7.2.0
- **jest**: ^29.7.0
- **joi**: ^17.13.1
- **jsonwebtoken**: ^9.0.2
- **mongodb**: ^6.6.1
- **mongoose**: ^8.3.5
- **pg**: ^8.11.5
- **sanitize-html**: ^2.13.0
- **sequelize**: ^6.37.3
- **socket.io**: ^4.7.5
- **winston**: ^3.13.0
- **winston-mongodb**: ^5.1.1

## Dev Dependencies

- **@eslint/js**: ^9.2.0
- **chai**: ^5.1.1
- **chai-http**: ^4.4.0
- **eslint**: ^8.57.0
- **eslint-config-airbnb**: ^19.0.4
- **eslint-config-airbnb-base**: ^15.0.0
- **eslint-plugin-import**: ^2.29.1
- **eslint-plugin-jsx-a11y**: ^6.8.0
- **eslint-plugin-react**: ^7.34.1
- **eslint-plugin-react-hooks**: ^4.6.2
- **globals**: ^15.2.0
- **mocha**: ^10.4.0
- **morgan**: ^1.10.0
- **nodemon**: ^3.1.0
