var  http   = require('http')
    ,https  = require('https')
    ,xpath  = require('xpath')
    ,dom    = require('xmldom').DOMParser
    ,util   = require('util')
    ,events = require('events');

(function () {

    function SimpleCASClient ()
    {
        events.EventEmitter.call(this);

        this.config = {
            session_space: 'simpleCAS',
            client: {
                prefix: null,
                host:   null,
                port:   null
            },
            server: {
                host:      null,
                port:      null,
                context:   null
            },
            initiating_url: null,
            callback_url:   null
        };

        this.configure = function( config )
        {
            if ( !config || typeof config == 'undefined' ) { return; }
            for ( var c in this.config )
            {
                if ( config.hasOwnProperty(c) )
                {
                    this.config[c] = config[c];
                }
            }
        };

        this.forceAuthentication = function( req,res )
        {
            /// auth is 4 step process
            /// 1) redirect user to CAS
            /// 2) CAS redirects back with TICKET in url
            /// 3) see TICKET in url : ask CAS who TICKET belongs to
            /// 4) CAS returns ticket-associated data : parse CAS data for user info

            var ticket        = this.checkRequestForTicket(req);
            var authenticated = this.isAuthenticated(req);

            var _this = this;
            try {
                if ( !authenticated && !ticket )
                {
                    this.redirectToCASLogin( req,res );
                } else if ( !authenticated && ticket ) {
                    this.validateTicket( req,res, ticket, function( data ) {
                        if ( 'session' in req ) {
                            req.session[_this.config.session_space] = data;
                            _this.emit('validation');
                            _this.redirectHereWithoutTicket( req,res )
                        } else {
                            _this.emit('error',new Error('Required Session Not Found'));
                        }
                    });
                } else if ( authenticated && ticket ) {
                    this.redirectHereWithoutTicket( req,res )
                } else if ( authenticated && !ticket ) {
                    _this.emit('success');
                }
            } catch (err) {
                _this.emit('error',err);
            }
        };

        this.logout = function( req,res )
        {
            if ( 'session' in req ) {
                req.session[this.config.session_space] = null;
                delete req.session[this.config.session_space];
            }
            this.redirectToCASLogout(req,res);
        };

        this.checkRequestForTicket = function ( req )
        {
            var ticket = req.param('ticket');
            return ( ticket ) ? ticket : false;
        };

        this.isAuthenticated = function ( req )
        {
            if ( ! ( 'session' in req && req.session ) ) {
                this.emit('error','Session required but not found');
                return false;
            }
            if ( ! ( this.config.session_space in req.session
                  && req.session[this.config.session_space] ) ) 
            {
                return false;
            }
            return ( 'user' in req.session[this.config.session_space]
                     && req.session[this.config.session_space].user );
        };

        this.getCallbackUrl = function( req )
        {
            return ( this.config.callback_url ) ? this.config.callback_url : this.getInitiatingUrl(req);
        };
        this.getInitiatingUrl = function( req )
        {
            var host = '';
            /// directly defined 
            if ( this.config.initiating_url ) {
                return this.config.initiating_url;
            }
            /// build from client config + request
            var initiating_url = '';
            if ( this.config.client.host ) {
                initiating_url = this.config.client.host;
                if ( this.config.client.prefix ) {
                    initiating_url = this.config.client.prefix + initiating_url;
                }
                return initiating_url + req.url;
            }

            /// build from forwarded proxy - only use 0
            if ( 'x-forwarded-host' in req.headers
                && req.headers['x-forwarded-host'] )
            {
                var hosts = req.headers['x-forwarded-host'].split(/\s*,\s*/);
                if ( hosts.length ) {
                    host = hosts[0];
                } else {
                    host = req.get['hostname'];
                }
            /// build from request only
            } else {
                host = req.get('hostname');
            }
            host = host.replace(/^\s+|\s+$/g,'');

            return req.protocol + "://" + host + req.url;

        };

        this.redirectToCASLogin = function ( req,res )
        {
            var callback_url = this.getCallbackUrl(req);
            var port = '';
            var protocol = 'https://';
            if ( this.config.server.port == '80' ) {
                protocol = 'http://';
            } else if ( this.config.port && this.config.server.port != '443' ) {
                port = ':'+this.config.server.port;
            }
            var return_url  = '?service='+ encodeURIComponent(callback_url);
            var redirect_to = protocol + this.config.server.host + port
                            + this.config.server.context + '/login' + return_url;
            res.redirect( redirect_to );
        };
        this.redirectToCASLogout = function ( req,res )
        {
            var callback_url = this.getCallbackUrl(req);
            var port = '';
            var protocol = 'https://';
            if ( this.config.server.port == '80' ) {
                protocol = 'http://';
            } else if ( this.config.port && this.config.server.port != '443' ) {
                port = ':'+this.config.server.port;
            }
            var return_url  = '?service='+ encodeURIComponent(callback_url);
            var redirect_to = protocol + this.config.server.host + port
                            + this.config.server.context + '/logout' + return_url;
            res.redirect( redirect_to );
        };
        this.redirectHereWithoutTicket = function( req,res )
        {
            var here_without_ticket = this.uniqueUrl( this.urlWithoutTicket( this.getInitiatingUrl(req) ) ); 
            res.redirect( here_without_ticket );
        };
        this.validateTicket = function ( req,res, ticket, next )
        {
            var requestor = ( this.config.server.port == '80' ) ? http : https;
            var service = encodeURIComponent( this.urlWithoutTicket( this.getInitiatingUrl(req) ) );
            var _this = this;
            var validation_request = requestor.get({
                host: this.config.server.host,
                port: this.config.server.port,
                path: this.config.server.context + '/serviceValidate?service='+service+'&ticket='+ticket,
                agent:  false,
                rejectUnauthorized: false,
                requestCert:        false
            }, function(validation_response){
                var body = '';
                validation_response.on('data', function(chunk){
                    body += chunk.toString('utf8');
                });
                validation_response.on('end', function(){
                    _this.parseResponseCAS20(body,function(result){
                        if ( !result.errors.length )
                        {
                            next(result);
                        } else {
                            _this.emit('failure', result.errors.join(', ') );
                        }
                    });
                });
                validation_response.on('error', function(err){
                    _this.emit('error',err);
                });
            });
            validation_request.on('error', function(err){
                _this.emit('error',err);
            });
            validation_request.end();
        };

        this.urlWithoutTicket = function( url )
        {
            return url.replace( /(^|[&?])ticket(=[^&]*)?/,'');
        };
        this.uniqueUrl = function( url )
        {
            var unique_url = url;
            unique_url += (url.indexOf('?')===-1)?'?':'&';
            unique_url +='_='+ new Date().getTime();
            return unique_url;
        };

        this.parseResponseCAS20 = function( cas_response, next )
        {
            var result = {
                user: null,
                attributes: {},
                errors: []
            };
            var cas20 = new dom().parseFromString(cas_response);

            var success_tags = xpath.select("//*[local-name()='authenticationSuccess']",cas20);
            if ( success_tags.length == 0 )
            {
                var failure_tags = xpath.select("//*[local-name()='authenticationFailure']",cas20);
                if ( failure_tags.length > 0 )
                {
                    for ( var f in failure_tags )
                    {
                        result.errors.push(failure_tags[f].nodeValue);
                    }
                }
                next(result);
                return;
            }

            var user_tags = xpath.select("//*[local-name()='authenticationSuccess']/*[local-name()='user' and namespace-uri(.)='http://www.yale.edu/tp/cas']/text()",cas20);
            for ( var u in user_tags )
            {
                result.user = user_tags[u].nodeValue;
            }
            if ( !result.user )
            {
                result.errors.push('Invalid Auth Response: Success Declared but no User given');
                next(result);
                return;
            }
            var attribute_tags = xpath.select("//*[local-name()='authenticationSuccess']/*/*[namespace-uri(.)='https://max.gov']/text()",cas20);
            for ( var a in attribute_tags )
            {
                result.attributes[ attribute_tags[a].parentNode.localName ] = attribute_tags[a].nodeValue;
            }

            next(result);
        };
    }

    util.inherits(SimpleCASClient, events.EventEmitter);
    exports.SimpleCASClient = SimpleCASClient;

}).call(this);
