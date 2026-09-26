const express = require('express');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const GOOGLE_REDIRECT_URI =
    'https://stunnas-world-oauth.onrender.com/oauth2callback';

const ALEXA_REDIRECT_URI =
    'https://layla.amazon.com/api/skill/link/M1K5UKMD390BCA';

const oauth2Client = new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
);

app.get('/', (req, res) => {
    res.send('Stunna\'s World OAuth Server is running!');
});

app.get('/authorize', (req, res) => {
    const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/spreadsheets'
        ],
        prompt: 'consent'
    });

    res.redirect(authUrl);
});

app.get('/oauth2callback', async (req, res) => {
    try {
        const { code } = req.query;

        if (!code) {
            return res.status(400).send('Authorization code is missing.');
        }

        const { tokens } = await oauth2Client.getToken(code);

        console.log('Google OAuth tokens received.');

        res.send(
            'Google authorization successful. You can close this window.'
        );

    } catch (error) {
        console.error('Google OAuth callback error:', error);
        res.status(500).send('Google authorization failed.');
    }
});

app.post(
    '/token',
    express.urlencoded({ extended: true }),
    async (req, res) => {
        try {
            const { code } = req.body;

            if (!code) {
                return res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Authorization code is required.'
                });
            }

            const { tokens } = await oauth2Client.getToken(code);

            res.json({
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                token_type: 'Bearer',
                expires_in: 3600
            });

        } catch (error) {
            console.error('Token exchange error:', error);

            res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Unable to exchange authorization code.'
            });
        }
    }
);

app.listen(PORT, () => {
    console.log(`OAuth server running on port ${PORT}`);
});
