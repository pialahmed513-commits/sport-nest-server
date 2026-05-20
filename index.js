const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { OAuth2Client } = require("google-auth-library");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const uri = process.env.MONGO_URI;

app.use(
  cors({
    origin: "https://sport-nest-server-pi.vercel.app/",
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const createToken = (user) => {
  return jwt.sign(
    {
      email: user.email,
      name: user.name,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
};

const setTokenCookie = (res, token) => {
  res.cookie("token", token, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

async function run() {
  try {
    await client.connect();

    const db = client.db("sport-nest");

    const usersCollection = db.collection("users");
    const facilitiesCollection = db.collection("facilities");
    const bookingsCollection = db.collection("bookings");

    app.post("/auth/register", async (req, res) => {
      try {
        const { name, email, photoURL, password } = req.body;

        if (!name || !email || !password) {
          return res.status(400).send({
            success: false,
            message: "Name, email and password are required",
          });
        }

        if (password.length < 6) {
          return res.status(400).send({
            success: false,
            message: "Password must be at least 6 characters",
          });
        }

        const existingUser = await usersCollection.findOne({ email });

        if (existingUser) {
          return res.status(409).send({
            success: false,
            message: "User already exists",
          });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userDoc = {
          name,
          email,
          photoURL: photoURL || "",
          password: hashedPassword,
          provider: "email",
          created_at: new Date(),
          last_login: new Date(),
        };

        await usersCollection.insertOne(userDoc);

        const token = createToken(userDoc);
        setTokenCookie(res, token);

        res.send({
          success: true,
          user: {
            name: userDoc.name,
            email: userDoc.email,
            photoURL: userDoc.photoURL,
            provider: userDoc.provider,
          },
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Registration failed",
          error: error.message,
        });
      }
    });

    app.post("/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res.status(400).send({
            success: false,
            message: "Email and password are required",
          });
        }

        const user = await usersCollection.findOne({ email });

        if (!user || !user.password) {
          return res.status(401).send({
            success: false,
            message: "Invalid email or password",
          });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
          return res.status(401).send({
            success: false,
            message: "Invalid email or password",
          });
        }

        await usersCollection.updateOne(
          { email },
          {
            $set: {
              last_login: new Date(),
            },
          }
        );

        const token = createToken(user);
        setTokenCookie(res, token);

        res.send({
          success: true,
          user: {
            name: user.name,
            email: user.email,
            photoURL: user.photoURL || "",
            provider: user.provider,
          },
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Login failed",
          error: error.message,
        });
      }
    });

    app.post("/auth/google", async (req, res) => {
      try {
        const { credential } = req.body;

        if (!credential) {
          return res.status(400).send({
            success: false,
            message: "Google credential is required",
          });
        }

        const ticket = await googleClient.verifyIdToken({
          idToken: credential,
          audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();

        const userInfo = {
          name: payload.name,
          email: payload.email,
          photoURL: payload.picture,
          provider: "google",
          last_login: new Date(),
        };

        await usersCollection.updateOne(
          { email: userInfo.email },
          {
            $set: userInfo,
            $setOnInsert: {
              created_at: new Date(),
            },
          },
          { upsert: true }
        );

        const token = createToken(userInfo);
        setTokenCookie(res, token);

        res.send({
          success: true,
          user: userInfo,
        });
      } catch (error) {
        res.status(401).send({
          success: false,
          message: "Google authentication failed",
          error: error.message,
        });
      }
    });

    app.get("/me", async (req, res) => {
      try {
        const token = req.cookies?.token;

        if (!token) {
          return res.send({
            success: false,
            user: null,
          });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await usersCollection.findOne(
          { email: decoded.email },
          {
            projection: {
              password: 0,
            },
          }
        );

        if (!user) {
          return res.send({
            success: false,
            user: null,
          });
        }

        res.send({
          success: true,
          user,
        });
      } catch (error) {
        res.send({
          success: false,
          user: null,
        });
      }
    });

    app.post("/logout", async (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
      });

      res.send({
        success: true,
        message: "Logged out successfully",
      });
    });

    app.get("/facilities", async (req, res) => {
      try {
        const realFacilities = await facilitiesCollection.find().toArray();
        let finalFacilities = [...realFacilities];

        if (finalFacilities.length > 0) {
          while (finalFacilities.length < 6) {
            finalFacilities = [...finalFacilities, ...realFacilities];
          }
        }

        res.send(finalFacilities);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: "Failed to fetch facilities",
          error: error.message,
        });
      }
    });

    app.post("/facilities", async (req, res) => {
      const facilityData = req.body;
      const result = await facilitiesCollection.insertOne(facilityData);
      res.send(result);
    });

    app.get("/my-facilities", async (req, res) => {
      const email = req.query.email?.trim();

      if (!email) {
        return res.send([]);
      }

      const result = await facilitiesCollection
        .find({ owner_email: email })
        .toArray();

      res.send(result);
    });

    app.get("/facilities/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid facility id",
        });
      }

      const result = await facilitiesCollection.findOne({
        _id: new ObjectId(id),
      });

      res.send(result);
    });

    app.patch("/facilities/:id", async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid facility id",
        });
      }

      const result = await facilitiesCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: updatedData,
        }
      );

      res.send({
        success: true,
        result,
      });
    });

    app.delete("/facilities/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid facility id",
        });
      }

      const result = await facilitiesCollection.deleteOne({
        _id: new ObjectId(id),
      });

      res.send({
        success: true,
        result,
      });
    });

    app.post("/bookings", async (req, res) => {
      const bookingData = req.body;

      const bookingDoc = {
        ...bookingData,
        status: "pending",
        created_at: new Date(),
      };

      const result = await bookingsCollection.insertOne(bookingDoc);

      res.send({
        success: true,
        result,
      });
    });

    app.get("/bookings", async (req, res) => {
      const result = await bookingsCollection.find().toArray();
      res.send(result);
    });

    app.get("/my-bookings", async (req, res) => {
      const email = req.query.email?.trim();

      if (!email) {
        return res.send([]);
      }

      const result = await bookingsCollection
        .find({ user_email: email })
        .toArray();

      res.send(result);
    });

    app.patch("/bookings/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          success: false,
          message: "Invalid booking id",
        });
      }

      const result = await bookingsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "cancelled",
            updated_at: new Date(),
          },
        }
      );

      res.send({
        success: true,
        result,
      });
    });

    await client.db("admin").command({ ping: 1 });
    console.log("✅ MongoDB connected successfully");
  } catch (error) {
    console.log("MongoDB connection error:", error.message);
  }
}

run();

app.get("/", (req, res) => {
  res.send("SportNest server is running");
});

module.exports = app;