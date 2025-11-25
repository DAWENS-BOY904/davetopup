// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { spawn } = require('child_process');
const nodemailer = require('nodemailer');
const cors = require('cors');
const Stripe = require('stripe');
const aws = require('aws-sdk');
const twilio = require('twilio');
const admin = require("firebase-admin");
const cron = require("node-cron");
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const fetch = require('node-fetch');

const app = express();

// ============ MIDDLEWARE ============
app.use(cors());
app.use(bodyParser.json());

// Static for local only (NOT Vercel)
if (!process.env.VERCEL) {
  app.use(express.static("public"));
}

// Upload
const upload = multer({ dest: 'uploads/' });

// ====== CONFIG ======
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const s3 = new aws.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.S3_REGION
});
const twClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'berryxoe@gmail.com';

// ====== MongoDB ======
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true, 
  useUnifiedTopology: true
})
.then(()=>console.log('MongoDB connected'))
.catch(err=>console.error('MongoDB error:', err));

// ====== Mock DB ======
let user = { username:"JohnDoe", about:"Hello!" };

// ====== Schemas ======
const txSchema = new mongoose.Schema({
  user: String,
  name: String,
  email: String,
  amount: Number,
  status: { type: String, default: 'pending' },
  method: String,
  createdAt: { type: Date, default: Date.now },
  payoutAt: Date,
  payoutNote: String,
  avatar: String
});
const Transaction = mongoose.model('Transaction', txSchema);

// ====== Middleware ======
function adminAuth(req,res,next){
  const authHeader = req.headers.authorization;
  if(!authHeader) return res.status(401).json({ error:'Unauthorized' });
  const token = authHeader.split(' ')[1];
  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if(decoded.role !== 'admin') throw new Error('Not admin');
    req.admin = decoded;
    next();
  }catch(err){
    return res.status(403).json({ error:'Forbidden' });
  }
}

// ============ ROUTES ============

// Home
app.get("/", (req, res) => {
  return res.sendFile(path.join(__dirname, "public/index.html"));
});

// --- Account ---
app.post('/api/account/update',(req,res)=>{
  const { username, about } = req.body;
  if(!username) return res.status(400).json({ message: "Username required" });
  user.username=username;
  user.about=about;
  res.json({ message:"Account updated" });
});
app.delete('/api/account/delete',(req,res)=>{
  user=null;
  res.json({ message:"Account deleted" });
});
app.get('/api/account/info',(req,res)=>res.json(user || { message:"No account found" }));

// --- Orders ---
let orders = {
  "12345": {
    id:"12345",
    name:"Jean Ray",
    email:"client@example.com",
    total:39.99,
    deliveryDate:"2025-11-13",
    deliveryTime:"14:30",
    tracking:["Commande reçue"]
  }
};

app.get("/orders/:id",(req,res)=>{
  const order = orders[req.params.id];
  if(!order) return res.status(404).json({ error:"Not found" });
  res.json(order);
});

// --- Update order ---
app.post("/orders/update", async (req,res)=>{
  const { id,date,time } = req.body;
  const order = orders[id];
  if(!order) return res.json({ success:false, message:"Commande introuvable" });

  order.deliveryDate=date;
  order.deliveryTime=time;
  const msg=`Livraison reprogrammée au ${date} à ${time}`;
  order.tracking.push(msg);

  // Email notification
  const transporter = nodemailer.createTransport({
    service:"gmail",
    auth:{
      user:process.env.EMAIL_USER,
      pass:process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from:"Dawens Library",
    to:order.email,
    subject:"Mise à jour de votre livraison 📦",
    text:`Bonjour ${order.name},\n\n${msg}\n\nMerci.\n— L’équipe Dawens Library`
  });

  res.json({ success:true });
});

// --- MonCash Payment ---
async function getAccessToken(){
  const formData = new URLSearchParams();
  formData.append('client_id', process.env.CLIENT_ID);
  formData.append('client_secret', process.env.CLIENT_SECRET);
  formData.append('grant_type', 'client_credentials');

  const res = await fetch("https://api.moncash.natcash.com/oauth/token",{ 
    method:"POST", 
    body:formData 
  });

  if(!res.ok) throw new Error("Erreur obtention token OAuth");

  return (await res.json()).access_token;
}

async function verifyPayment(token,orderId){
  const res = await fetch(
    `https://api.moncash.natcash.com/V1/RetrieveTransactionPayment?reference=${orderId}`, 
    { method:"GET", headers:{ "Authorization":`Bearer ${token}` }}
  );

  if(!res.ok) throw new Error("Erreur récupération transaction");

  return await res.json();
}

app.post('/api/payment', upload.single('proof'), async (req,res)=>{
  try{
    const { orderId } = req.body;
    if(!req.file) return res.status(400).json({ status:"error", message:"Pas de preuve uploadée" });

    const token = await getAccessToken();
    const result = await verifyPayment(token, orderId);

    if(result.status==="success"){
      const newPath = path.join('uploads',`${orderId}_${req.file.originalname}`);
      fs.renameSync(req.file.path,newPath);
      return res.json({ status:"success", message:"Paiement vérifié" });
    } else {
      fs.unlinkSync(req.file.path);
      return res.json({ status:"error", message:result.message });
    }
  }catch(err){ 
    res.status(500).json({ status:"error", message:err.message });
  }
});

// --- AI Python Fallback (Vercel can't spawn Python) ---
app.post('/api/gemini', async (req,res)=>{
  return res.json({ error: "Python not supported on Vercel serverless" });
});

// --- ChatGPT ---
app.post('/api/chat', async (req,res)=>{
  const { prompt } = req.body;
  try{
    const response = await fetch('https://api.openai.com/v1/chat/completions',{
      method:'POST',
      headers:{
        'Content-Type':'application/json',
        'Authorization':`Bearer ${process.env.OPENAI_KEY}`
      },
      body: JSON.stringify({
        model:"gpt-3.5-turbo",
        messages:[{role:"user",content:prompt}],
        temperature:0.7,
        max_tokens:250
      })
    });
    const data = await response.json();
    const reply = data.choices[0].message.content.trim();
    res.json({ reply });
  }catch(err){
    res.status(500).json({ reply:"Erreur serveur" });
  }
});

// --- ADMIN ROUTES ---
app.post('/api/admin/login', async (req,res)=>{
  const { username,password } = req.body;
  if(username==='admin' && password==='password123'){
    const token = jwt.sign(
      { username:'admin',role:'admin' },
      process.env.JWT_SECRET,
      { expiresIn:'12h' }
    );
    return res.json({ token });
  }
  res.status(401).json({ error:'Invalid credentials' });
});


// my try
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});
const db = admin.firestore();

// Gmail SMTP
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "kontgithub@gmail.com",
    pass: "zmhf mtdj ztub oysq"
  }
});

// 👉 1) API ROUTE : SEND EMAIL IMMEDIATELY WHEN USER LOGS IN
app.post("/send-login-email", async (req, res) => {
  const email = req.body.email;
  if (!email) return res.json({ error: "No email provided" });

  try {
    await transporter.sendMail({
      from: "kontgithub@gmail.com",
      to: email,
      subject: "Welcome Back!",
      text: "Mèsi paske ou login sou DaveTopUp!"
    });
    res.json({ success: true });
  } catch (err) {
    res.json({ error: err.message });
  }
});

// 👉 2) CRON JOB: Send email every 2 days
cron.schedule("0 10 */2 * *", async () => {
  console.log("⏰ Sending 2-day emails...");

  const users = await db.collection("users").get();

  users.forEach(async (doc) => {
    const email = doc.data().email;

    await transporter.sendMail({
      from: "berryxoe@gmail.com",
      to: email,
      subject: "DaveTopUp Reminder",
      text: "Nou toujou la pou ou! Pa bliye tcheke DaveTopUp 🚀"
    });
  });

});

// ====== EXPORT FOR VERCEL ======
module.exports = app;
