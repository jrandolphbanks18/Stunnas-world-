const express = require('express');
const crypto = require('crypto');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// CONFIGURATION
// =====================================================

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Google sends the user back here after authorization.
const GOOGLE_REDIRECT_URI =
    'https://stunnas-world-oauth.onrender.com/oauth2callback';

// Alexa sends the user back here after our authorization server
// has generated an authorization code.
const ALEXA_REDIRECT_URI =
    'https://layla.amazon.com/api/skill/link/M1K5UKMD390BCA';

// Create your own Alexa OAuth client credentials in Render.
// DO NOT use your Google Client ID/Secret for these.
const ALEXA_CLIENT_ID = process.env.ALEXA_CLIENT_ID;
const ALEXA_CLIENT_SECRET = process.env.ALEXA_CLIENT_SECRET;

// Temporary authorization-code storage.
// For a production system, use a persistent database.
const authorizationCodes = new Map();

// =====================================================
// GOOGLE OAUTH CLIENT
// =====================================================

const googleOAuth = new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
);

// =====================================================
// HOME / HEALTH CHECK
// =====================================================

app.get('/', (req, res) => {
    res.send("Stunna's World OAuth Server is running!");
});

// =====================================================
// ALEXA AUTHORIZATION ENDPOINT
// =====================================================

app.get('/authorize', (req, res) => {
    try {
        const {
            client_id,
            redirect_uri,
            state,
            response_type,
            scope,
            code_challenge,
            code_challenge_method
        } = req.query;

        console.log('Alexa authorization request received.');
        console.log(JSON.stringify(req.query, null, 2));

        // Verify Alexa client.
        if (client_id !== ALEXA_CLIENT_ID) {
            return res.status(401).send('Invalid client.');
        }

        // Verify response type.
        if (response_type !== 'code') {
            return res.status(400).send('Unsupported response type.');
        }

        // Verify redirect URI.
        if (redirect_uri !== ALEXA_REDIRECT_URI) {
            return res.status(400).send('Invalid redirect URI.');
        }

        // Require PKCE.
        if (
            !code_challenge ||
            code_challenge_method !== 'S256'
        ) {
            return res.status(400).send('PKCE is required.');
        }

        // Preserve Alexa's OAuth information while sending
        // the user to Google.
        const googleState = Buffer.from(
            JSON.stringify({
                state,
                alexaRedirectUri: redirect_uri,
                codeChallenge: code_challenge
            })
        ).toString('base64url');

        const googleAuthorizationUrl =
            googleOAuth.generateAuthUrl({
                access_type: 'offline',
                scope: [
                    'https://www.googleapis.com/auth/spreadsheets'
                ],
                prompt: 'consent',
                state: googleState
            });

        res.redirect(googleAuthorizationUrl);

    } catch (error) {
        console.error('Authorization endpoint error:', error);
        res.status(500).send('Authorization failed.');
    }
});

// =====================================================
// GOOGLE CALLBACK
// =====================================================

app.get('/oauth2callback', async (req, res) => {
    try {
        const { code, state } = req.query;

        if (!code || !state) {
            return res.status(400).send(
                'Google authorization response is missing information.'
            );
        }

        const stateData = JSON.parse(
            Buffer.from(state, 'base64url').toString('utf8')
        );

        // Exchange Google's authorization code for tokens.
        const { tokens } = await googleOAuth.getToken(code);

        if (!tokens.access_token) {
            return res.status(400).send(
                'Google did not return an access token.'
            );
        }

        // Generate a temporary authorization code for Alexa.
        const alexaCode = crypto.randomBytes(32).toString('hex');

        authorizationCodes.set(alexaCode, {
            googleAccessToken: tokens.access_token,
            googleRefreshToken: tokens.refresh_token,
            expiresAt: Date.now() + 5 * 60 * 1000,
            codeChallenge: stateData.codeChallenge
        });

        // Send the authorization code back to Alexa.
        const redirectUrl = new URL(
            stateData.alexaRedirectUri
        );

        redirectUrl.searchParams.set(
            'code',
            alexaCode
        );

        redirectUrl.searchParams.set(
            'state',
            stateData.state
        );

        res.redirect(redirectUrl.toString());

    } catch (error) {
        console.error(
            'Google callback error:',
            error
        );

        res.status(500).send(
            'Google authorization failed.'
        );
    }
});

// =====================================================
// ALEXA TOKEN ENDPOINT
// =====================================================

app.post(
    '/token',
    express.urlencoded({ extended: true }),
    async (req, res) => {
        try {
            const {
                grant_type,
                code,
                client_id,
                client_secret,
                redirect_uri,
                code_verifier
            } = req.body;

            console.log(
                'Alexa token request received.'
            );

            // Verify Alexa client credentials.
            if (
                client_id !== ALEXA_CLIENT_ID ||
                client_secret !== ALEXA_CLIENT_SECRET
            ) {
                return res.status(401).json({
                    error: 'invalid_client'
                });
            }

            // Authorization-code exchange.
            if (grant_type === 'authorization_code') {

                if (!code) {
                    return res.status(400).json({
                        error: 'invalid_request'
                    });
                }

                if (redirect_uri !== ALEXA_REDIRECT_URI) {
                    return res.status(400).json({
                        error: 'invalid_grant'
                    });
                }

                const storedCode =
                    authorizationCodes.get(code);

                if (!storedCode) {
                    return res.status(400).json({
                        error: 'invalid_grant'
                    });
                }

                // Check expiration.
                if (storedCode.expiresAt < Date.now()) {
                    authorizationCodes.delete(code);

                    return res.status(400).json({
                        error: 'invalid_grant'
                    });
                }

                // Verify PKCE.
                if (!code_verifier) {
                    return res.status(400).json({
                        error: 'invalid_grant'
                    });
                }

                const calculatedChallenge =
                    crypto
                        .createHash('sha256')
                        .update(code_verifier)
                        .digest('base64url');

                if (
                    calculatedChallenge !==
                    storedCode.codeChallenge
                ) {
                    return res.status(400).json({
                        error: 'invalid_grant'
                    });
                }

                // Authorization codes are single-use.
                authorizationCodes.delete(code);

                return res.json({
                    access_token:
                        storedCode.googleAccessToken,

                    refresh_token:
                        storedCode.googleRefreshToken,

                    token_type: 'Bearer',

                    expires_in: 3600
                });
            }

            return res.status(400).json({
                error: 'unsupported_grant_type'
            });

        } catch (error) {
            console.error(
                'Token endpoint error:',
                error
            );

            res.status(500).json({
                error: 'server_error'
            });
        }
    }
);

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {
    console.log(
        `Stunna's World OAuth Server running on port ${PORT}`
    );
});
