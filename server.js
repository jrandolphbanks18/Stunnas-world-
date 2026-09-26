const express = require('express');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 3000;

// Google OAuth credentials
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Alexa redirect URI
const ALEXA_REDIRECT_URI =
    'https://layla.amazon.com/api/skill/link/M1K5UKMD390BCA';

const oauth2Client = new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    ALEXA_REDIRECT_URI
);

// Health check
app.get('/', (req, res) => {
    res.send('Stunna\'s World OAuth Server is running!');
});

// Authorization endpoint
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

// Token endpoint
app.post('/token', express.urlencoded({ extended: true }), async (req, res) => {
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
});

app.listen(PORT, () => {
    console.log(`OAuth server running on port ${PORT}`);
});
