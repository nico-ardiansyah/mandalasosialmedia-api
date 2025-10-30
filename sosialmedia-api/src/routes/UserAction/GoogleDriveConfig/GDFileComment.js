const { google } = require("googleapis");

// google drive client
const Client_Id = process.env.CLIENT_ID;
const Client_Secret = process.env.CLIENT_SECRET;
const Redirect_Url = process.env.REDIRECT_URL;
const Refresh_Token = process.env.REFRESH_TOKEN_GD_FILECOMMENT;

const oauth2client = new google.auth.OAuth2(
    Client_Id,
    Client_Secret,
    Redirect_Url,
);

oauth2client.setCredentials({ refresh_token: Refresh_Token });

const GDCommentConfig = google.drive({
    version: 'v3',
    auth: oauth2client
});

module.exports = GDCommentConfig;