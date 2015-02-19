var passport = require('passport-strategy');
var util = require('util');
var google = require('googleapis');
var oauth2 = google.oauth2('v2');

// GoogleAPIsStrategy constructor
function GoogleAPIsStrategy(options, verify) {

  // Check if options object was passed or only verify callback
  if(typeof options === 'function') {
    verify = options;
    options = undefined;
  }

  // Set options to empty if not supplied
  options = options || {};

  // Check that we have a verify callback
  if(!verify) {
    throw new TypeError('GoogleAPIsStrategy requires a verify callback');
  }

  // Check that we have a clientID option
  if(!options.clientID) {
    throw new TypeError('GoogleAPIsStrategy requires a clientID option');
  }

  // Check that we have a clientSecret option
  if(!options.clientSecret) {
    throw new TypeError('GoogleAPIsStrategy requires a clientSecret option');
  }

  // Check that we have a redirectURL option
  if(!options.redirectURL) {
    throw new TypeError('GoogleAPIsStrategy requires a redirectURL option')
  }

  // Call Passport Strategy constructor with this scope
  passport.Strategy.call(this);

  // Set name of strategy
  this.name = 'googleapis';

  // Set verify callback on strategy
  this._verify = verify;

  // Create Google OAuth2 client and set on strategy
  this.oauth2Client = new google.auth.OAuth2(options.clientID, options.clientSecret, options.redirectURL);
};

// Inherit from Passport Strategy class
util.inherits(GoogleAPIsStrategy, passport.Strategy);

// Override authenticate() middleware.
// Function is passed the request object and an options object, which
// should have a scope property with Google auth scope(s).
// This function get's called twice, once before the Google auth screen is
// shown to the user, and once after. Function should exit by calling one of:
// success(user, info) - authenticate a user
// fail(challenge, status) - fail authentication attempt
// pass() - don't make a success or fail decision (shouldn't use)
// error(err) - internal error during authentication
GoogleAPIsStrategy.prototype.authenticate = function(req, options) {

  // Set options to empty if not supplied
  options = options || {};

  // Reference to this to simplify callbacks
  var self = this;

  // Check if the request query has an error parameter
  if(req.query && req.query.error) {
    // Check if this error is 'access_denied' and handle it
    if(req.query.error === 'access_denied') {
      // Fail this attempt due to access denied
      return this.fail({message: req.query.error_description});
    } else {
      // Return this error as we're unsure what it might be
      return this.error(new Error(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  // Check if the request query has a code parameter
  // This means successful user auth, but now need to obtain a token
  if(req.query && req.query.code) {
    var code = req.query.code;

    // Attempt to obtain token
    self.oauth2Client.getToken(code, function(err, tokens) {
      // Check for error
      if(err) {
        // Stop here, return the error
        return self.error(self._createOAuthError('Failed to obtain access token', err));
      }

      // No error, we have tokens
      var accessToken = tokens.access_token;
      var refreshToken = tokens.refresh_token || null;

      // Set these tokens on the Google OAuth2 client
      self.oauth2Client.setCredentials(tokens);

      // Attempt to get user info
      oauth2.userinfo.get({auth: self.oauth2Client}, function(err, profile) {
        // Check for error
        if(err) {
          // Stop here, return the error
          return self.error(err);
        }

        // Define function to pass as verify callback
        function verified(err, user, info) {
          // Check for error
          if(err) {
            // Stop here, return the error
            return self.error(err);
          }

          // Check for no user
          if(!user) {
            // Fail authentication on account of no user
            return self.fail(info);
          }

          // Otherwise success
          self.success(user, info);
        }

        // Determine how many arguments to send to verify callback
        try {
          // Check if we should pass the request to verify as first argument
          if(self._passReqToCallback) {
            var arity = self._verify.length;
            if(arity === 6) {
              self._verify(req, accessToken, refreshToken, {}, profile, verified);
            } else {
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else {
            // Don't pass request to callback
            var arity = self._verify.length;
            if(arity === 5) {
              self._verify(accessToken, refreshToken, {}, profile, verified);
            } else {
              self._verify(accessToken, refreshToken, profile, verified);
            }
          }
        } catch(ex) {
          // Return this exception as eror
          return self.error(ex);
        }
      });
    });
  } else {
    // No code parameter on the request query
    // Get authorization parameters from options
    var params = this.authorizationParams(options);

    // Create authentication URL
    var location = this.oauth2Client.generateAuthUrl(params);

    // Redirect the request to the authentication url
    this.redirect(location);
  }
};

// Create authorization params object
GoogleAPIsStrategy.prototype.authorizationParams = function(options) {
  // Initial empty parameter object
  var params = {};

  // See if scope was passed with options
  var scope = options.scope || this._scope;
  if(scope) {
    // Set scope parameter if set
    params.scope = scope;
  }

  // See if access_type was passed with options
  if(options.accessType || options.access_type) {
    // Set access_type parameter if set
    params.access_type = options.accessType || options.access_type;
  }

  // Return parameters
  return params;
}

// Helper method to parse errors from Google
GoogleAPIsStrategy.prototype.parseErrorResponse = function(body, status) {
  // Parse error body as JSON
  var json = JSON.parse(body);

  // Check if error JSON has error property set
  if(json.error) {
    // Use JSON to create error and return
    return new Error(json.error_description, json.error, json.error_uri);
  }

  // Return null if no error property
  return null;
}

// Helper method to create OAuth error from message and error
GoogleAPIsStrategy.prototype._createOAuthError = function(message, err) {
  // Initial empty error variable
  var e;

  // See if error has statusCode and data properties
  if(err.statusCode && err.data) {
    // Attempt to parse error data as JSON
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }

  // If parse failed or didn't return anything, create Error
  if(!e) {
    e = new Error(message, err);
  }

  // Return error
  return e;
};

// Export Strategy
exports.Strategy = exports.GoogleAPIsStrategy = GoogleAPIsStrategy;
