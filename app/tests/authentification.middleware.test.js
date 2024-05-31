// Unitary test using mocha chai
import * as chai from 'chai';
import authentificationMiddleware from '../middlewares/authentification.middleware.js';
import ApiError from '../errors/api.error.js';

const { expect } = chai;

describe('Authentification middleware', () => {
  it('should refuse the request if no token is provided', (done) => {
    const req = {
      cookies: {}, // No token
    };

    const res = {};

    const next = (err) => {
      expect(err).to.be.instanceOf(ApiError);
      expect(err.status).to.equal(401);
      expect(err.message).to.equal('Unauthorized');
      expect(err.details).to.equal('No token provided');
      done();
    };

    authentificationMiddleware(req, res, next);
  });
  it('should refuse the request if the token is invalid', (done) => {
    const req = {
      cookies: {
        token: 'invalid-token',
      },
    };

    const res = {};

    const next = (err) => {
      expect(err).to.be.instanceOf(ApiError);
      expect(err.status).to.equal(401);
      expect(err.message).to.equal('Unauthorized');
      expect(err.details).to.equal("You don't have access to this resource");
      done();
    };

    authentificationMiddleware(req, res, next);
  });
});
