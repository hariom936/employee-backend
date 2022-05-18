const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");

const routes = require("./routes/routes");

const app = express();
dotenv.config();

app.get("/", (req, res) => {
  res.send("App running");
});

const port = 3001;

app.listen(port, () => {
  console.log(`App running on port ${port}`);
});

mongoose
  .connect(process.env.DB_CONNECT, { useNewUrlParser: true })
  .then(() => {
    console.log("Database connected");
  })
  .catch((error) => console.log(error));

app.use(express.json(), cors());

app.use("/", routes);
