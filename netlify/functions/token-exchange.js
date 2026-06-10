// Netlify serverless function — QBO token exchange
// Runs server-side so Client Secret never touches the browser

exports.handler = async (event) => {
  // Only allow POST
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  // CORS headers — allow requests from this Netlify site only
  const headers = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    const { code, code_verifier, grant_type, refresh_token } = JSON.parse(event.body || '{}');

    const CLIENT_ID     = process.env.QBO_CLIENT_ID;
    const CLIENT_SECRET = process.env.QBO_CLIENT_SECRET;
    const REDIRECT_URI  = process.env.QBO_REDIRECT_URI;
    const TOKEN_URL     = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';

    if (!CLIENT_ID || !CLIENT_SECRET) {
      return { statusCode: 500, headers, body: JSON.stringify({ error: 'Server misconfigured — missing env vars' }) };
    }

    // Build request body based on grant type
    const params = new URLSearchParams();
    if (grant_type === 'refresh_token') {
      params.set('grant_type',    'refresh_token');
      params.set('refresh_token', refresh_token);
    } else {
      params.set('grant_type',    'authorization_code');
      params.set('code',          code);
      params.set('redirect_uri',  REDIRECT_URI);
      params.set('code_verifier', code_verifier);
    }

    // Basic auth header using Client ID + Secret
    const basicAuth = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const response = await fetch(TOKEN_URL, {
      method:  'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type':  'application/x-www-form-urlencoded',
        'Accept':        'application/json'
      },
      body: params.toString()
    });

    const tok = await response.json();

    if (!tok.access_token) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: tok.error_description || tok.error || 'Token exchange failed', raw: tok })
      };
    }

    // Add expires_at timestamp (in ms for JS Date.now() compatibility)
    tok.expires_at = Date.now() + (tok.expires_in * 1000);

    return { statusCode: 200, headers, body: JSON.stringify(tok) };

  } catch (e) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: e.message })
    };
  }
};
