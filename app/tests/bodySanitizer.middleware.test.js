// Unitary test using mocha chai
import * as chai from 'chai';
import * as chaiHttp from 'chai-http';
import sanitizeBodyMiddleware from '../middlewares/bodySanitizer.middleware.js';

chai.use((chai) => {
  chai.request = chaiHttp;
});

const { expect } = chai;

describe('Body Sanitizer middleware', () => {
  it('should sanitize the body of the request', (done) => {
    const req = {
      body: {
        text: '<script>alert("Hello")</script>',
      },
    };
    const res = {};
    const next = () => {
      expect(req.body.text).to.equal('');
      done();
    };

    sanitizeBodyMiddleware(req, res, next);
  });

  it('should not sanitize the body of the request', (done) => {
    const req = {
      body: {
        text: 'Hello',
      },
    };
    const res = {};
    const next = () => {
      expect(req.body.text).to.equal('Hello');
      done();
    };

    sanitizeBodyMiddleware(req, res, next);
  });
});
