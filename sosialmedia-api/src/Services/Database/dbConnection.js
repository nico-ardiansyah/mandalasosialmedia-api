require("dotenv").config();
const pkg = require("pg");
const { Pool } = pkg

const dbPoll = new Pool({
  connectionString: process.env.DB_URL, // postgresql://username:password@host:5432/postgres
  ssl: { rejectUnauthorized: false }, // penting untuk supabase
});

dbPoll.connect()
  .then(client => {
    console.log("✅ Database connected successfully!");
    client.release(); // lepas koneksi kembali ke pool
  })
  .catch(err => {
    console.error("❌ Database connection failed:", err.message);
  });

module.exports = dbPoll;
