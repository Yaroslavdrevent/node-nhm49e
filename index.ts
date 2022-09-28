const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const { joiPasswordExtendCore } = require('joi-password');
const joiPassword = joi.extend(joiPasswordExtendCore);
const app = express();
const bodyParser = require('body-parser');
const port = 3000;

import { Request, Response } from 'express';
import { memoryUsage } from 'process';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

// Validate user object using joi
// - username (required, min 3, max 24 characters)
// - email (required, valid email address)
// - type (required, select dropdown with either 'user' or 'admin')
// - password (required, min 5, max 24 characters, upper and lower case, at least one special character)

var jsonParser = bodyParser.json();

const userValidSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid('user', 'admin').required(),
  password: joiPassword
    .string()
    .min(5)
    .max(24)
    // .minOfLowercase(1)
    // .minOfUppercase(1)
    .minOfSpecialCharacters(1)
    .required()
    .messages({
      'password.minOfUppercase':
        '{#label} should contain at least {#min} uppercase character',
      'password.minOfSpecialCharacters':
        '{#label} should contain at least {#min} special character',
      'password.minOfLowercase':
        '{#label} should contain at least {#min} lowercase character',
      'password.min': '{#label} should contain at least {#min} characters',
      'password.max': '{#label} should contain less than {#max} characters',
    }),
});

function getUserByUsername(name: string): UserEntry | undefined {
  // TODO
  if (name === undefined || name === null) return undefined;
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  // TODO
  const username = (Object.keys(MEMORY_DB) as Array<string>).find(
    (key) => MEMORY_DB[key].email === email
  );
  if (username === undefined) return undefined;
  return MEMORY_DB[username];
}

// Request body -> UserDto
/////////// changed get into post from the original code   //////
//   app.get('/register', (req: Request, res: Response) => {   //
/////////////////////////////////////////////////////////////////
app.post('/register', jsonParser, (req: Request, res: Response) => {
  const newUser: UserDto = req.body;
  const result = userValidSchema.validate(newUser);
  if (result.error) res.status(400).end(result.error.details[0].message);
  else {
    // check if username and email existance using helper functions
    if (getUserByEmail(newUser.email))
      res.status(200).end('The email already exists');
    else if (getUserByUsername(newUser.username))
      res.status(200).end('The username already exists');

    // create a userEntry instance and store into MEMORY_DB
    const user: UserEntry = {
      email: newUser.email,
      type: newUser.type,
      salt: 'RANDOM_STRING',
      passwordhash: bcrypt.hashSync(newUser.password, 10),
    };
    MEMORY_DB[newUser.username] = user;
    res.status(200).send('new user registered');
  }
});

// Request body -> { username: string, password: string }
app.post('/login', jsonParser, (req: Request, res: Response) => {
  const payload = req.body;
  const user = getUserByUsername(payload.username);
  if (!user || !bcrypt.compareSync(payload.password, user.passwordhash))
    res.status(401).end('username or password is incorrect');
  else res.status(200).end('login successfully');
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
