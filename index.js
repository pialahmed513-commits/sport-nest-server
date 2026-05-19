const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const uri = process.env.MONGO_URI;

app.use(cors());
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const db = client.db("sport-nest");
    const facilitiesCollection = db.collection("facilities");
    const bookingsCollection = db.collection("bookings");

    app.get("/facilities", async (req, res) => {
      const result = await facilitiesCollection.find().toArray();
      res.send(result);
    });

    app.post("/facilities", async (req, res) => {
      const facilityData = req.body;
      const result = await facilitiesCollection.insertOne(facilityData);
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
      const email = req.query.email;

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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});