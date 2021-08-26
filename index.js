// MODULES //

const express = require('express');
const fs = require('fs');
const saml = require('samlify');
const validator = require( '@authenio/samlify-node-xmllint' );
const axios = require('axios');
const bodyParser = require( 'body-parser' );
const debug = require('debug')( 'samlify' );


// MAIN //

const app = express();
app.use( bodyParser.urlencoded({ 
	extended: true 
}) );
app.use( bodyParser.json() );

saml.setSchemaValidator( validator );

// URL to the Identity Provider metadata:
const URI_IDP_METADATA = 'https://samltest.id/saml/idp';

axios.get( URI_IDP_METADATA ).then( response => {

	const idp = saml.IdentityProvider({
		metadata: response.data,
		isAssertionEncrypted: true,
		messageSigningOrder: 'encrypt-then-sign',
		wantLogoutRequestSigned: true
	});

	const sp = saml.ServiceProvider({
		entityID: 'https://isle-hub.stat.cmu.edu/shibboleth',
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
	app.post('/sp/acs', async (req, res) => {
		debug( 'Received /sp/acs post request...' );
		try {
			const { extract } = await sp.parseLoginResponse(idp, 'post', req);
			return res.send( JSON.stringify( extract.attributes ) );
		} catch ( e ) {
			console.error( '[FATAL] when parsing login response...', e );
			return res.redirect( '/' );
		}
	});

	/**
	* Endpoint for initiating the login process.
	*/
	app.get('/login', async (req, res) => {
		const { id, context } = await sp.createLoginRequest( idp, 'redirect' );
		debug( 'Context: %s', context );
		debug( 'Id: %s', id );
		return res.redirect(context);
	});

	/**
	* Endpoint to retrieve the Identity Provider metadata.
	*/ 
	app.get('/idp/metadata', (req, res) => {
		res.header( 'Content-Type', 'text/xml' ).send( idp.getMetadata() );
	});

	/**
	* Endpoint to retrieve the Service Provider's metadata.
	*/
	app.get('/sp/metadata', ( req, res ) => {
		res.header( 'Content-Type','text/xml' ).send( sp.getMetadata() );
	});

	/**
	* Start the server.
	*/
	app.listen( 8001, () => {
		console.log(`Example app listening at http://localhost:8001`)
	})
});

