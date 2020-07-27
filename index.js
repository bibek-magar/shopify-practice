const dotenv = require("dotenv").config();
const express = require("express");
const app = express();
const crypto = require("crypto");
const nonce = require("nonce");
const querystring = require("querystring");
const request = require("request-promise");
const cookie = require("cookie");
const axios = require("axios");

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = "write_products";
const forwardingAddress = "https://0e002bb5f641.ngrok.io";

app.get("/shopify", (req, res) => {
  const shop = req.query.shop;
  if (shop) {
    const state = nonce();
    const redirectUri = forwardingAddress + "/shopify/callback";
    const installUrl =
      "https://" +
      shop +
      "/admin/oauth/authorize?client_id=" +
      apiKey +
      "&scope=" +
      scopes +
      "&state=" +
      state +
      "&redirect_uri=" +
      redirectUri;

    res.cookie("state", state);
    res.redirect(installUrl);
  } else {
    return res
      .status(400)
      .send(
        "missing shop parameter. Please add ?shop=your-development-shop.shopify.com to your request"
      );
  }
});

app.get("/shopify/callback", (req, res) => {
  const { shop, hmac, code, state } = req.query;
  const stateCookie = cookie.parse(req.headers.cookie).state;

  console.log(state);
  console.log(stateCookie);

  if (state != stateCookie) {
    return res.status(403).send("Request origin cannot be verified");
  }

  if (shop && hmac && code) {
    const map = Object.assign({}, req.query);
    delete map["hmac"];
    const message = querystring.stringify(map);
    const generatedHash = crypto
      .createHmac("sha256", apiSecret)
      .update(message)
      .digest("hex");

    if (generatedHash !== hmac) {
      return res.status(400).send("HMAC validation failed");
    }

    const accessTokenRequestUrl =
      "https://" + shop + "/admin/oauth/access_token";

    const accessTokenPayload = {
      client_id: apiKey,
      client_secret: apiSecret,
      code,
    };

    request
      .post(accessTokenRequestUrl, { json: accessTokenPayload })
      .then((accessTokenResponse) => {
        const accessToken = accessTokenResponse.access_token;
        res.status(200).send("Got an access token, let's do something with it");
      })
      .catch((error) =>
        res.status(error.statusCode).send(error.error.error_description)
      );

    const apiRequestUrl = "https://" + shop + "/admin/shop.json";
    const shopRequestHeader = {
      "X-Shopify-Access-Token": accessToken,
    };
    request
      .get(apiRequestUrl, { headers: shopRequestHeader })
      .them((apiResponse) => {
        res.end(shopResponse);
      })
      .catch((error) => {
        res.status(error.statusCode).send(error.error.error_description);
      });
  } else {
    req.status(400).send("Required parameters missing");
  }
});

app.listen(3000, () => {
  console.log("Listening to port 3000");
});

app.get("/shopify/get-inventory", async (req, res) => {
  const url = process.env.SHOPIFY_STORE_URL;

  try {
    const add = await axios.get(
      "https://" +
        process.env.SHOPIFY_API_KEY +
        ":" +
        process.env.SHOPIFY_API_SECRET +
        "@" +
        url +
        "@" +
        "/admin/api/2020-07/products.json"
    );

    res.send(add);
  } catch (error) {
    res.send(error);
    console.log(error);
  }
});
