require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require ("multer");
const path = require("path");
const { off } = require("process");
const fs = require ("fs").promises;


const app = express();
const PORT = process.env.PORT || 5001;


app.use(cors());
app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/productUploads", express.static(path.join(__dirname,"productUploads")));

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: 5432, 
});



pool.connect()
  .then(() => console.log(" Connected to PostgreSQL"))
  .catch((err) => {
    console.error(" PostgreSQL connection error:", err);
    process.exit(1);
  });


(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(100) NOT NULL,
      password VARCHAR(255) NOT NULL,
      profile_image VARCHAR(255)
    )
  `);
  console.log(" Users table ready");


  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      productName VARCHAR(255) NOT NULL,
      price NUMERIC NOT NULL,
      description TEXT,
      tags JSON,
      productCategory VARCHAR(100),
      image JSON
    )
  `);
  console.log("Products table ready");

})();


const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, "uploads/"); 
  },
  filename: function(req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname); 
  }
});
 
const uploads=multer({storage});

const productStorage = multer.diskStorage({
 destination: (req, file, cb) => {
  cb(null, path.join(__dirname, "productUploads"));
},

  filename: (req, file, cb) => {
    
    if (!req.uploadTimestamp) req.uploadTimestamp = Date.now();

    const ext = path.extname(file.originalname).toLowerCase();
    const uniqueSuffix = Math.floor(Math.random() * 10000); 
    const filename = `${req.uploadTimestamp}-${uniqueSuffix}${ext}`;
    cb(null, filename);
  },
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (![".jpg", ".jpeg", ".png"].includes(ext)) {
    return cb(new Error("Only .jpg, .jpeg, .png allowed"));
  }
  cb(null, true);
};


const productUploads = multer({ storage: productStorage,fileFilter});

const authenticate = (req,res,next)=>{
  const token = req.headers["authentication"];
  if(!token) return res.status(401).json({message:"No token provided"});
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch(err) {
    res.status(401).json({message:"Invalid token"});
  }
};



app.post("/register", async (req, res) => {
  console.log("Register requset recieved");
  const { username, email, password } = req.body;
  console.log("Requst body:",req.body);
  if (!username || !email || !password) return res.status(400).json({ message: "All fields are required" });

  try {
    console.log("checking if username exist");
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
    if (existing.rows.length > 0) return res.status(400).json({ message: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 8);
    console.log("inserting user database");
    await pool.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [username, email, hashedPassword]);
    console.log(`new user registered:${username}`);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "All fields required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ message: "Invalid username" });

    const user = result.rows[0];
    if (user.email !== email) return res.status(400).json({ message: "Invalid email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
    console.log("Generrated JWT token:",token);

    const { password: _, ...userWithoutPassword } = user;
    res.json({ message: "Login successful", user: userWithoutPassword, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/dashboard/add-users", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 5;
  const offset = (page - 1) * limit;

  try {
    const usersResult = await pool.query("SELECT id, username, email FROM users ORDER BY id LIMIT $1 OFFSET $2", [limit, offset]);
    const countResult = await pool.query("SELECT COUNT(*) AS total FROM users");
    const totalUsers = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({ page, limit, totalUsers, totalPages, users: usersResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/dashboard/add-user", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ message: "All fields required" });

  try {
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
    if (existing.rows.length > 0) return res.status(400).json({ message: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 8);
    await pool.query("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", [username, email, hashedPassword]);

    res.status(201).json({ message: "Dashboard user added successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.delete("/users/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const result = await pool.query("DELETE FROM users WHERE username=$1 RETURNING *", [username]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/profile",authenticate,async(req,res)=>{
  try{
    const result=await pool.query(
      "SELECT id,username,email,profile_image FROM users WHERE id=$1",
      [req.user.id]
    );
    if(result.rows.length===0) return res.status(401).json({message:"user not found"});
    res.json(result.rows[0]);
  }catch(err){
    console.error(err);
    res.status(500).json({message:"Server error"});
  }
});
app.put("/profile", authenticate, uploads.single("profile_image"), async (req, res) => {
  const { username, email } = req.body;
  const newProfileImage = req.file ? req.file.filename : null; 

  try {
   
    const userResult = await pool.query("SELECT profile_image FROM users WHERE id=$1", [req.user.id]);
    if (userResult.rows.length === 0) return res.status(404).json({ message: "User not found" });

    const oldImage = userResult.rows[0].profile_image;

    
    if (newProfileImage && oldImage) {
      const oldImagePath = path.join(__dirname, "uploads", oldImage);
      try {
        await fs.access(oldImagePath);      
        await fs.unlink(oldImagePath);       
      } catch (err) {
        console.warn("Old image not found or already deleted:", oldImagePath);
      }
    }

    const result = await pool.query(
      `UPDATE users
       SET username=$1,
           email=$2,
           profile_image = COALESCE($3, profile_image)
       WHERE id=$4
       RETURNING id, username, email, profile_image`,
      [username, email, newProfileImage, req.user.id]
    );

    res.json({ message: "Profile updated successfully", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/change-password",authenticate,async(req,res)=>{
  const { oldPassword,newPassword } = req.body;

  if(!oldPassword || !newPassword)
    return res.status(400).json({message:"All fields are required"});

  try{
    const result= await pool.query("SELECT password FROM users WHERE id=$1",[req.user.id]);
    if(result.rows.length === 0)
      return res.status(400).json({message:"user not found"});

    const isMatch = await bcrypt.compare(oldPassword,result.rows[0].password);
    if(!isMatch)
      return res.status(400).json({message:"Old password is incorrect"});

    const hashedPassword = await bcrypt.hash(newPassword,8);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2",[hashedPassword,req.user.id]);

    res.json({message:"Password updated succesfully"});
  }catch(err){
    console.error(err);
    res.status(500).json({message:"Server error"});
  }
});

app.post("/products", productUploads.array("productImage"), async (req, res) => {
   console.log("FILES RECEIVED:", req.files); 
  console.log("BODY:", req.body);
  try {
    const { productName, price, description, tags, productCategory } = req.body;
    const parsedTags = JSON.parse(tags);

  
    const imageFilenames = req.files.map(file => file.filename);

    await pool.query(
      `INSERT INTO products (productName, price, description, tags, productCategory, image)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [productName, price, description, parsedTags, productCategory, JSON.stringify(imageFilenames)]
    );

    res.status(201).json({ message: "Product created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.get("/addproduct", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const productResult = await pool.query(
      `SELECT id,
              productname AS "productName",
              price,
              description,
              tags,
              productcategory AS "productCategory",
              image
       FROM products
       ORDER BY id
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    const products = productResult.rows.map((product) => ({
      ...product,
      tags: Array.isArray(product.tags) ? product.tags : [],
      image: Array.isArray(product.image) ? product.image : [],
    }));

    const countResult = await pool.query("SELECT COUNT(*) AS total FROM products");
    const totalProduct = parseInt(countResult.rows[0].total);
    const totalPage = Math.ceil(totalProduct / limit);

    res.json({ page, limit, totalProduct, totalPage, products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/products/:id/likes", async (req, res) => {
  try {
    const { id } = req.params;       
    const { userid } = req.body;     

    const userId=parseInt(userid);  
    const productId=parseInt(id);

    if(!userId || !productId){
      return res.status(400).json({message:"userId and productId is required"}) 
    }

    const result = await pool.query(
      "SELECT * FROM addlikes WHERE userid=$1 AND productid=$2",
      [userId, productId]
    );

    if (result.rows.length === 0) {
      
      await pool.query(
        "INSERT INTO addlikes (userid, productid, likes) VALUES ($1, $2, 1)",
        [userId, productId]);

      await pool.query(
        "UPDATE products SET likes = COALESCE(likes, 0) + 1 WHERE id=$1",
        [productId]);

      return res.status(200).json({ message: "Liked successfully", liked: true });
    } else {
      await pool.query(
        "DELETE FROM addlikes WHERE userid=$1 AND productid=$2",
        [userId, productId]);

      await pool.query(
        "UPDATE products SET likes = GREATEST(COALESCE(likes, 1) - 1, 0) WHERE id=$1",
        [productId]);

      return res.status(200).json({ message: "Unliked successfully", liked: false });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


app.listen(PORT, () => {
  console.log(`🚀 PostgreSQL API running at http://localhost:${PORT}`);
});
