// MODULES //

const express = require( 'express' );
const fs = require( 'fs' );
const cookieSession = require( 'cookie-session' );
const saml = require( 'samlify' );
const validator = require( '@authenio/samlify-node-xmllint' );
const axios = require( 'axios' );
const bodyParser = require( 'body-parser' );
const debug = require('debug')( 'samlify' );


// MAIN //

const app = express();
app.use( bodyParser.urlencoded({ 
	extended: true 
}) );
app.use( bodyParser.json() );

app.use( cookieSession({
	name: 'session',
	keys: [ 'my-favorite-secret' ]
}) );

saml.setSchemaValidator( validator );

// URL to the Identity Provider metadata:
const URI_IDP_METADATA = 'https://samltest.id/saml/idp';

axios.get( URI_IDP_METADATA ).then( response => {

	/**
	* Instantiates a SAML identity provider.
	*
	* ## Notes
	*
	* -   Documentation for the configuration object for the `IdentityProvider` can be found [here](https://samlify.js.org/#/idp-configuration)
	*/
	const idp = saml.IdentityProvider({
		metadata: response.data,
		isAssertionEncrypted: true,
		messageSigningOrder: 'encrypt-then-sign',
		wantLogoutRequestSigned: true
	});

	/**
	* Instantiates a SAML service provider.
	*
	* ## Notes
	*
	* -   Documentation for the configuration object for the `ServiceProvider` can be found [here](https://samlify.js.org/#/sp-configuration)
	*/
	const sp = saml.ServiceProvider({
		entityID: 'https://isle-hub.stat.cmu.edu/shibboleth', // SP entity ID
		authnRequestsSigned: false,
		wantAssertionsSigned: false,
		wantMessageSigned: false, 
		wantLogoutResponseSigned: false,
		wantLogoutRequestSigned: false,
		signingCert: fs.readFileSync( '/etc/shibboleth/sp-signing-cert.pem' ),
		// the private key (.pem) use to sign the assertion; 
		privateKey: fs.readFileSync( '/etc/shibboleth/sp-signing-key.pem' ),       
		// the private key pass;
		// privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',                     
		// the private key (.pem) use to encrypt the assertion;
		encryptCert: fs.readFileSync( '/etc/shibboleth/sp-encrypt-cert.pem' ),
		encPrivateKey: fs.readFileSync( '/etc/shibboleth/sp-encrypt-key.pem' ),             
		isAssertionEncrypted: true,
		assertionConsumerService: [{
			Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
			Location: 'https://isle-hub.stat.cmu.edu/shibboleth/sp/acs',
		}]
	});

	/**
	* This is the endpoint that the IdP will redirect to after the user logs in.
	* 
	* The IdP will send a SAML response with the user's attributes to this endpoint.
	*/
	app.post('/sp/acs', async ( req, res ) => {
		debug( 'Received /sp/acs post request...' );

		const relayState = req.headers.relayState;

		// console.log( 'Session: ' );
		// console.log( req.session );

		try {
			const { extract } = await sp.parseLoginResponse( idp, 'post', req );
			console.log( 'Extract: ' );
			console.log( extract );
			req.session.loggedIn = true;
			req.session.attributes = extract.attributes;
			return res.send( JSON.stringify( extract.attributes ) );
		} catch ( e ) {
			console.error( '[FATAL] when parsing login response...', e );
			return res.redirect( '/' );
		}
	});

	/**
	* Endpoint for initiating the login process.
	*/
	app.get( '/login', ( req, res ) => {
		const { id, context } = sp.createLoginRequest( idp, 'redirect' );
		debug( 'Id: %s', id );

		const serverURL = req.protocol + '://' + req.get( 'host' );
		context.relayState = req.query.url || serverURL;
		debug( 'Context: %s', context );
		return res.redirect( context );
	});

	/**
	* Endpoint to retrieve the Identity Provider metadata.
	*/ 
	app.get( '/idp/metadata', (req, res) => {
		res.header( 'Content-Type', 'text/xml' ).send( idp.getMetadata() );
	});

	/**
	* Endpoint to retrieve the Service Provider's metadata.
	*/
	app.get( '/sp/metadata', ( req, res ) => {
		res.header( 'Content-Type','text/xml' ).send( sp.getMetadata() );
	});

	app.get( '/*', ( req, res, next ) => {
		if ( !req.session.loggedIn ) {
			return res.redirect( `/shibboleth/login?url=${encodeURI( req.originalUrl )}` );
		}
		next();
	});

	app.get( '/greeting', ( req, res ) => {
		const name = req.session.attributes[ 'urn:oid:2.5.4.42' ] || 'Anonymous';
		res.send( `Hello, ${name}!` );
	});

	/**
	* Start the server.
	*/
	app.listen( 8001, () => {
		console.log(`Example app listening at http://localhost:8001`)
	})
});

