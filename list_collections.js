const mongo = require("mongodb");
const MongoClient = mongo.MongoClient;

async function processDB() {
  const url = "mongodb://127.0.0.1:27017";
  const client = new MongoClient(url, { monitorCommands: true });

  client.on("commandStarted", (data) => console.log("commandStarted:", data));
  client.on("commandSucceeded", (data) => console.log("commandFailed:", data));
  client.on("commandFailed", (data) => console.log("commandFailed:", data));

  try {
    await client.connect();

    const db = client.db("local");

    const collections = await db.listCollections().toArray();
    console.log(collections);
  } catch (err) {
    console.error(err);
  } finally {
    await client.close();
  }
}

processDB();
