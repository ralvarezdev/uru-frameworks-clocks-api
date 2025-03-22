import 'dotenv/config';
import express from 'express';
import helmet from "helmet";
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {initializeApp} from "firebase/app";
import {getAuth, GoogleAuthProvider, createUserWithEmailAndPassword, signInWithEmailAndPassword, signInWithPopup, signOut} from "firebase/auth";
import cookieParser from 'cookie-parser'
import {ErrorHandler, HandleValidation, FieldFailError, SuccessJSendBody} from '@ralvarezdev/js-express'
import {Validate} from '@ralvarezdev/js-joi-parser'
import Joi from 'joi';
import {IS_PROD, loadNode} from "@ralvarezdev/js-mode";

// Load Node
loadNode()

// Constants
const PORT = process.env.URU_FRAMEWORKS_CLOCKS_API_PORT
const COOKIE_ACCESS_TOKEN_NAME = process.env.URU_FRAMEWORKS_CLOCKS_API_COOKIE_ACCESS_TOKEN_NAME
const COOKIE_ACCESS_TOKEN_MAX_AGE = parseInt(process.env.URU_FRAMEWORKS_CLOCKS_API_COOKIE_ACCESS_TOKEN_MAX_AGE)

// Initialize Firebase
initializeApp({
  apiKey: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_API_KEY,
  authDomain: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_PROJECT_ID,
  storageBucket: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_APP_ID,
  measurementId: process.env.URU_FRAMEWORKS_CLOCKS_API_FIREBASE_MEASUREMENT_ID
});

// Get the Auth service
const auth = getAuth();

// Google Sign-In
const provider = new GoogleAuthProvider();

// Resolve the paths to the server and browser distribution folders
const serverDistFolder = dirname(fileURLToPath(import.meta.url));
const browserDistFolder = resolve(serverDistFolder, '../browser');

// Create a cookie with the user ID
function createCookieWithUserId(res, userId) {
  res.cookie(COOKIE_ACCESS_TOKEN_NAME, userId, {
    httpOnly: true,
    secure: IS_PROD(),
    maxAge: COOKIE_ACCESS_TOKEN_MAX_AGE * 1000,
  });
}

/**
 * Create an Express application instance.
 */
const app = express();
const errorHandler = new ErrorHandler()

// Add the cookie parser middleware
app.use(cookieParser())

// Add the body parser middleware
app.use(express.json())

// Add the error JSON body parser handler middleware
app.use(errorHandler.errorJSONBodyParserCatcher())

// Add the url encoded body parser middleware
app.use(express.urlencoded({extended: true}));

// Add Helmet middleware for security
app.use(helmet());

/**
 * Sign up a new user with email and password
 */
app.post('/api/sign-up', async (req, res, next) => {
  // Validate the request
  const {email, password} = HandleValidation(req,
    res,
    (req) => Validate(
      req,
      Joi.object({
        password: Joi.string().required().min(1),
        email: Joi.string().email().required().email(),
      })
    )
  );

  try {
    // Create the user with email and password
    await createUserWithEmailAndPassword(auth, email, password)

    // Send the success response
    res.status(200).json(SuccessJSendBody())
  } catch(error) {
    if (error?.code==='auth/email-already-in-use' || error?.code==='auth/invalid-email')
      error = FieldFailError(400, 'email', error?.message)
    else if (error?.code==='auth/weak-password')
      error = FieldFailError(400, 'password', error?.message)

    // Continue with the error
    next(error)
  }
});

/*
 * Sign in a user with email and password
 */
app.post('/api/sign-in', async (req, res, next) => {
  // Validate the request
  const {email, password} = HandleValidation(req,
    res,
    (req) => Validate(
      req,
      Joi.object({
        password: Joi.string().required().min(1),
        email: Joi.string().email().required().email(),
      })
    )
  );

  try {
    // Sign in the user
    const userCredential = await signInWithEmailAndPassword(auth, email, password)

    // Create a cookie with the user ID
    createCookieWithUserId(res, userCredential.user.uid)

    // Send the success response
    res.status(200).json(SuccessJSendBody())
  } catch (error) {
    if (error?.code === 'auth/user-not-found' || error?.code === 'auth/invalid-email')
      error = FieldFailError(401, 'email', error?.message)
    else if (error?.code === 'auth/wrong-password')
      error = FieldFailError(401, 'password', error?.message)

    // Continue with the error
    next(error)
  }
})

/*
 * Sign in a user with Google
 */
app.post('/api/sign-in/google', async (req, res, next) => {
  try {
    // Sign in the user with Google
    const userCredential = await signInWithPopup(auth, provider)

    // Create a cookie with the user ID
    createCookieWithUserId(res, userCredential.user.uid)

    // Send the success response
    res.status(200).json(SuccessJSendBody())
  } catch (error) {
    // Continue with the error
    next(error)
  }
})

/*
 * Sign out the user and remove the cookie
 */
app.post('/api/sign-out', async (req, res, next) => {
  // Sign out the user
  try {
    await signOut(auth)

    // Clear the user ID cookie
    res.clearCookie(COOKIE_ACCESS_TOKEN_NAME)

    // Send the success response
    res.status(200).json(SuccessJSendBody())
  } catch (error) {
    // Continue with the error
    next(error)
  }
})

/**
 * Serve static files from /browser
 */
app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

// Add the error catcher middleware
app.use(errorHandler.errorCatcher())

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});