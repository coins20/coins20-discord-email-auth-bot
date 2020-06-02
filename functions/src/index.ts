import * as functions from 'firebase-functions';
import fetch from 'node-fetch';
import FormData from 'form-data';
import * as crypto from 'crypto';
import * as config from './config.json'

function getUserById(id: string) {
  for (const user of config.users) {
    if (user.id === id) {
      return user;
    }
  }
  return null;
}

function getUserByEmail(email: string) {
  for (const user of config.users) {
    if (user.email === email) {
      return user;
    }
  }
  return null;
}

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript
//
export const getEmail = functions.https.onCall((data, context) => {
  const user = getUserById(data.id);
  if (!user) {
    throw new functions.https.HttpsError('not-found', 'User not found');
  }
  return {
    email: user.email
  };
});

export const getDiscordAuthURL = functions.https.onCall((data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required");
  }
  const clientID = functions.config().discord.client_id;
  const redirectURI = functions.config().discord.redirect_uri;
  const state = crypto.randomBytes(22).toString('hex');
  const href = 'https://discordapp.com/api/oauth2/authorize?response_type=code&client_id='+clientID+'&scope=identify%20guilds.join&state='+state+'&redirect_uri='+redirectURI+'&prompt=consent';
  return {
    href: href,
    state: state,
  };
});

export const authDiscord = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required");
  }
  console.log(context.auth);
  if (!context.auth.token.email_verified) {
    throw new functions.https.HttpsError('unauthenticated', "not verified");
  }

  const user = getUserByEmail(context.auth.token.email);
  if (!user) {
    throw new functions.https.HttpsError('unauthenticated', 'No user linked');
  }

  const body = new FormData();
  body.append('client_id', functions.config().discord.client_id);
  body.append('client_secret', functions.config().discord.client_secret);
  body.append('grant_type', 'authorization_code')
  body.append('code', data.code);
  body.append('redirect_uri', functions.config().discord.redirect_uri);
  body.append('scope', 'identify');

  const tokenResult = await fetch('https://discordapp.com/api/v6/oauth2/token', { method: 'POST', body: body });
  const tokenResponse = await tokenResult.json();
  if (tokenResult.status !== 200) {
    console.error(`${tokenResult.status} ${tokenResult.status}: ${JSON.stringify(tokenResponse)}`);
    throw new functions.https.HttpsError('internal', 'Failed to retreive token');
  }

  const userResult = await fetch('https://discordapp.com/api/v6/users/@me', {
    headers: {
      'Authorization': 'Bearer ' + tokenResponse.access_token
    }
  });
  const userResponse = await userResult.json();
  if (userResult.status !== 200) {
    console.error(`${userResult.status} ${userResult.status}: ${JSON.stringify(userResponse)}`);
    throw new functions.https.HttpsError('internal', 'Failed to retreive user');
  }
  console.log(userResponse);

  const joinResult = await fetch(`https://discordapp.com/api/v6/guilds/${functions.config().discord.guild_id}/members/${userResponse.id}`, {
    method: 'PUT',
    headers: {
      'Authorization': 'Bot ' + functions.config().discord.bot_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ access_token: tokenResponse.access_token, roles: user.roles }),
  });
  if (joinResult.status !== 201 && joinResult.status !== 204) {
    console.error(`${joinResult.status} ${joinResult.status}`);
    console.error(await joinResult.text());
    throw new functions.https.HttpsError('internal', 'Failed to add member');
  }

  for (const role of user.roles) {
    const updateResult = await fetch(`https://discordapp.com/api/v6/guilds/${functions.config().discord.guild_id}/members/${userResponse.id}/roles/${role}`, {
      method: 'PUT',
      headers: {
        'Authorization': 'Bot ' + functions.config().discord.bot_token
      }
    });
    if (updateResult.status !== 204) {
      console.error(`${updateResult.status} ${updateResult.status}`);
      console.error(await updateResult.text());
      throw new functions.https.HttpsError('internal', 'Failed to add to member');
    }
  }

  return {
    discord_name: userResponse.username + '#' + userResponse.discriminator
  };
});
