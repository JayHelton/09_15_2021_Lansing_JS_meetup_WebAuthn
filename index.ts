import http from "http";

import express from "express";

import cookieParser from "cookie-parser";
import bodyParser from "body-parser";

import registerWebAuthnRouter from "./routes/webauthn";
import { LoggedInUser } from "./routes/webauthn";

const app = express();
const host = "0.0.0.0";
const port =  process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.static("./public/"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {};

app.get("/logout", (_req, res) => {
  res.clearCookie("user");
  res.redirect("/");
});

const verifyUser = (req, res, next) => {
  const user = inMemoryUserDeviceDB[req.cookies.user];
  if (!user) {
    return res.status(404).send("not found");
  }
  res.locals.user = user;
  next();
}

app.get("/api/user", verifyUser, (req, res) => {
  const user = res.locals.user;
  if (user?.loggedIn) {
    res.send(user);
  } else {
    res.status(401).send("unauthorized");
  }
});

app.use("/api/webauthn", registerWebAuthnRouter(inMemoryUserDeviceDB));

http.createServer({}, app).listen(port, host, () => {
  console.log(`🚀 Server ready at http://${host}:${port}`);
});
