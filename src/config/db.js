const mongoose = require("mongoose");
const connectDB = async () => {
  try {
    console.log(process.env.MongoURL);
    const con = await mongoose.connect(process.env.MongoURL);
    console.log("Mongo DB connected : " + con.connection.host);
  } catch (err) {
    console.log(`Error : ${err.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;

