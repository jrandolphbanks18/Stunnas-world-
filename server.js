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

const GOOGLE_REDIRECT_URI =
    'https://stunnas-world-oauth.onrender.com/oauth2callback';

const ALEXA_REDIRECT_URI =
    'https://layla.amazon.com/api/skill/link/M1K5UKMD390BCA';

const ALEXA_CLIENT_ID = process.env.ALEXA_CLIENT_ID;
const ALEXA_CLIENT_SECRET = process.env.ALEXA_CLIENT_SECRET;

// Temporary authorization-code storage.
// For production, use a database.
const authorizationCodes = new Map();

// Temporary refresh-token storage.
// For production, use a database.
const refreshTokens = new Map();

// =====================================================
// GOOGLE OAUTH CLIENT
// =====================================================

const googleOAuth = new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
);

// =====================================================
// EXPRESS
// =====================================================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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

        console.log('==========================================');
        console.log('Alexa authorization request received');
        console.log(JSON.stringify(req.query, null, 2));
        console.log('==========================================');

        // -------------------------------------------------
        // Verify Alexa client
        // -------------------------------------------------

        if (client_id !== ALEXA_CLIENT_ID) {
            console.error('Invalid Alexa client ID.');
            return res.status(401).send('Invalid client.');
        }

        // -------------------------------------------------
        // Verify response type
        // -------------------------------------------------

        if (response_type !== 'code') {
            return res.status(400).send(
                'Unsupported response type.'
            );
        }

        // -------------------------------------------------
        // Verify redirect URI
        // -------------------------------------------------

        if (redirect_uri !== ALEXA_REDIRECT_URI) {
            console.error('Invalid Alexa redirect URI.');
            return res.status(400).send(
                'Invalid redirect URI.'
            );
        }

        // -------------------------------------------------
        // Require PKCE
        // -------------------------------------------------

        if (
            !code_challenge ||
            code_challenge_method !== 'S256'
        ) {
            console.error('Missing or invalid PKCE.');
            return res.status(400).send(
                'PKCE is required.'
            );
        }

        // -------------------------------------------------
        // Preserve Alexa OAuth information
        // -------------------------------------------------

        const googleState = Buffer.from(
            JSON.stringify({
                state,
                alexaRedirectUri: redirect_uri,
                codeChallenge: code_challenge,
                codeChallengeMethod: code_challenge_method
            })
        ).toString('base64url');

        // -------------------------------------------------
        // Send user to Google
        // -------------------------------------------------

        const googleAuthorizationUrl =
            googleOAuth.generateAuthUrl({
                access_type: 'offline',

                scope: [
                    'https://www.googleapis.com/auth/spreadsheets'
                ],

                prompt: 'consent',

                state: googleState
            });

        console.log(
            'Redirecting user to Google authorization.'
        );

        res.redirect(googleAuthorizationUrl);

    } catch (error) {
        console.error(
            'Authorization endpoint error:',
            error
        );

        res.status(500).send(
            'Authorization failed.'
        );
    }
});

// =====================================================
// GOOGLE CALLBACK
// =====================================================

app.get('/oauth2callback', async (req, res) => {
    try {
        const { code, state } = req.query;

        console.log('==========================================');
        console.log('Google OAuth callback received');
        console.log('==========================================');

        if (!code || !state) {
            return res.status(400).send(
                'Google authorization response is missing information.'
            );
        }

        // -------------------------------------------------
        // Decode state
        // -------------------------------------------------

        const stateData = JSON.parse(
            Buffer.from(
                state,
                'base64url'
            ).toString('utf8')
        );

        // -------------------------------------------------
        // Exchange Google authorization code
        // -------------------------------------------------

        const { tokens } =
            await googleOAuth.getToken(code);

        console.log(
            'Google token response received.'
        );

        if (!tokens.access_token) {
            return res.status(400).send(
                'Google did not return an access token.'
            );
        }

        // -------------------------------------------------
        // Google must provide a refresh token
        // -------------------------------------------------

        if (!tokens.refresh_token) {
            console.error(
                'Google did not provide a refresh token.'
            );

            return res.status(400).send(
                'Google did not provide a refresh token. Please try linking again.'
            );
        }

        // -------------------------------------------------
        // Generate Alexa authorization code
        // -------------------------------------------------

        const alexaCode =
            crypto.randomBytes(32).toString('hex');

        // -------------------------------------------------
        // Store Google credentials temporarily
        // -------------------------------------------------

        authorizationCodes.set(
            alexaCode,
            {
                googleAccessToken:
                    tokens.access_token,

                googleRefreshToken:
                    tokens.refresh_token,

                expiresAt:
                    Date.now() + (5 * 60 * 1000),

                codeChallenge:
                    stateData.codeChallenge,

                codeChallengeMethod:
                    stateData.codeChallengeMethod
            }
        );

        // -------------------------------------------------
        // Send authorization code back to Alexa
        // -------------------------------------------------

        const redirectUrl =
            new URL(
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

        console.log(
            'Redirecting authorization code back to Alexa.'
        );

        res.redirect(
            redirectUrl.toString()
        );

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
// TOKEN ENDPOINT
// =====================================================

app.post('/token', async (req, res) => {
    try {
        const {
            grant_type,
            code,
            client_id,
            client_secret,
            redirect_uri,
            code_verifier,
            refresh_token
        } = req.body;

        console.log('==========================================');
        console.log('Alexa token request received');
        console.log('Grant type:', grant_type);
        console.log('==========================================');

        // -------------------------------------------------
        // Read HTTP Basic credentials
        // -------------------------------------------------

        let basicClientId = null;
        let basicClientSecret = null;

        const authorizationHeader =
            req.headers.authorization;

        if (
            authorizationHeader &&
            authorizationHeader.startsWith('Basic ')
        ) {
            try {
                const encodedCredentials =
                    authorizationHeader.substring(6);

                const decodedCredentials =
                    Buffer
                        .from(
                            encodedCredentials,
                            'base64'
                        )
                        .toString('utf8');

                const separatorIndex =
                    decodedCredentials.indexOf(':');

                if (separatorIndex !== -1) {
                    basicClientId =
                        decodedCredentials.substring(
                            0,
                            separatorIndex
                        );

                    basicClientSecret =
                        decodedCredentials.substring(
                            separatorIndex + 1
                        );
                }

            } catch (error) {
                console.error(
                    'Unable to decode Basic authentication.'
                );
            }
        }

        // -------------------------------------------------
        // Accept credentials from either:
        // HTTP Basic OR request body
        // -------------------------------------------------

        const receivedClientId =
            basicClientId || client_id;

        const receivedClientSecret =
            basicClientSecret || client_secret;

        // -------------------------------------------------
        // Verify Alexa credentials
        // -------------------------------------------------

        if (
            receivedClientId !== ALEXA_CLIENT_ID ||
            receivedClientSecret !== ALEXA_CLIENT_SECRET
        ) {
            console.error(
                'Invalid Alexa client credentials.'
            );

            return res.status(401).json({
                error: 'invalid_client'
            });
        }

        // =================================================
        // AUTHORIZATION CODE GRANT
        // =================================================

        if (
            grant_type ===
            'authorization_code'
        ) {

            if (!code) {
                return res.status(400).json({
                    error: 'invalid_request'
                });
            }

            // -------------------------------------------------
            // Verify redirect URI
            // -------------------------------------------------

            if (
                redirect_uri &&
                redirect_uri !== ALEXA_REDIRECT_URI
            ) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Find stored authorization code
            // -------------------------------------------------

            const storedCode =
                authorizationCodes.get(code);

            if (!storedCode) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Check expiration
            // -------------------------------------------------

            if (
                storedCode.expiresAt <
                Date.now()
            ) {
                authorizationCodes.delete(code);

                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Require PKCE verifier
            // -------------------------------------------------

            if (!code_verifier) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Calculate PKCE challenge
            // -------------------------------------------------

            const calculatedChallenge =
                crypto
                    .createHash('sha256')
                    .update(code_verifier)
                    .digest('base64url');

            // -------------------------------------------------
            // Verify PKCE
            // -------------------------------------------------

            if (
                calculatedChallenge !==
                storedCode.codeChallenge
            ) {
                console.error(
                    'PKCE verification failed.'
                );

                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Authorization code is single-use
            // -------------------------------------------------

            authorizationCodes.delete(code);

            // -------------------------------------------------
            // Generate our own refresh token
            // -------------------------------------------------

            const stunnasRefreshToken =
                crypto.randomBytes(48).toString('hex');

            refreshTokens.set(
                stunnasRefreshToken,
                {
                    googleRefreshToken:
                        storedCode.googleRefreshToken
                }
            );

            // -------------------------------------------------
            // Return access + refresh token
            // -------------------------------------------------

            return res.json({
                access_token:
                    storedCode.googleAccessToken,

                refresh_token:
                    stunnasRefreshToken,

                token_type:
                    'Bearer',

                expires_in:
                    3600
            });
        }

        // =================================================
        // REFRESH TOKEN GRANT
        // =================================================

        if (
            grant_type ===
            'refresh_token'
        ) {

            if (!refresh_token) {
                return res.status(400).json({
                    error: 'invalid_request'
                });
            }

            // -------------------------------------------------
            // Find stored refresh token
            // -------------------------------------------------

            const storedRefreshToken =
                refreshTokens.get(
                    refresh_token
                );

            if (!storedRefreshToken) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Create Google OAuth client
            // -------------------------------------------------

            const refreshOAuth =
                new google.auth.OAuth2(
                    GOOGLE_CLIENT_ID,
                    GOOGLE_CLIENT_SECRET,
                    GOOGLE_REDIRECT_URI
                );

            refreshOAuth.setCredentials({
                refresh_token:
                    storedRefreshToken.googleRefreshToken
            });

            // -------------------------------------------------
            // Get new Google access token
            // -------------------------------------------------

            const {
                credentials
            } =
                await refreshOAuth.refreshAccessToken();

            if (!credentials.access_token) {
                return res.status(400).json({
                    error: 'invalid_grant'
                });
            }

            // -------------------------------------------------
            // Return refreshed access token
            // -------------------------------------------------

            return res.json({
                access_token:
                    credentials.access_token,

                refresh_token:
                    refresh_token,

                token_type:
                    'Bearer',

                expires_in:
                    3600
            });
        }

        // =================================================
        // UNSUPPORTED GRANT
        // =================================================

        return res.status(400).json({
            error: 'unsupported_grant_type'
        });

    } catch (error) {
        console.error(
            'Token endpoint error:',
            error
        );

        return res.status(500).json({
            error: 'server_error'
        });
    }
});

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {
    console.log(
        `Stunna's World OAuth Server running on port ${PORT}`
    );
});
