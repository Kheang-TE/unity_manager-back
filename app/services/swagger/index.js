import expressJSDocSwagger from 'express-jsdoc-swagger';

const options = {
  info: {
    version: '1.0.0',
    title: 'Unity Manager API',
    description: 'API documentation for Unity Manager',
    license: {
      name: 'BSD',
    },
  },
  baseDir: './app/routers',
  filesPattern: './**/*.js',
  swaggerUIPath: '/api-docs', // Expose l'interface utilisateur Swagger
  exposeSwaggerUI: true,
};

/**
 * Initialize the swagger documentation
 * @param {object} app - The express app
 */
function initSwagger(app) {
  expressJSDocSwagger(app)(options);
}

export default initSwagger;
