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
const paypal = require('@paypal/checkout-server-sdk');
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

/* -------------------------
   Stripe Setup & Route
   ------------------------- */
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-08-16' });

app.post('/api/checkout/stripe', async (req, res) => {
  try {
    const { planId, price, metadata } = req.body;
    // Validate planId & price server-side!
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: `Plan ${planId}` },
            unit_amount: Math.round(parseFloat(price) * 100)
          },
          quantity: 1
        }
      ],
      mode: 'payment',
      success_url: `${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin}/cancel.html`,
      metadata: metadata || {}
    });

    return res.json({ sessionId: session.id, publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: err.message });
  }
});

// Stripe webhook (verify signature)
app.post('/webhook/stripe', express.raw({type: 'application/json'}), (req,res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.WEBHOOK_SECRET_STRIPE);
  } catch (err) {
    console.error('Webhook signature error', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    // TODO: mark order paid in DB using session.metadata or session.id
    console.log('Stripe paid session', session.id);
  }
  res.json({received:true});
});
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

/* -------------------------
   PayPal Setup & Route
   ------------------------- */
const environment = new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET);
const paypalClient = new paypal.core.PayPalHttpClient(environment);

app.post('/api/checkout/paypal', async (req, res) => {
  const { planId, price } = req.body;
  try {
    // Create order
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: "CAPTURE",
      purchase_units: [{
        amount: { currency_code: "USD", value: String(price) },
        description: `Plan ${planId}`
      }],
      application_context: {
        return_url: `${req.headers.origin}/paypal-success.html`,
        cancel_url: `${req.headers.origin}/paypal-cancel.html`
      }
    });

    const order = await paypalClient.execute(request);
    const approve = order.result.links.find(l => l.rel === 'approve');
    res.json({ approveUrl: approve.href, orderId: order.result.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// PayPal webhook route (example)
app.post('/webhook/paypal', bodyParser.json(), (req, res) => {
  // Validate webhook with PayPal (requires verifying transmission id & signature)
  console.log('PayPal webhook received', req.body);
  res.json({received:true});
});

/* -------------------------
   Binance Pay route
   ------------------------- */
/*
  Binance Pay requires you to sign the payload and POST to their create order endpoint.
  See Binance Pay merchant docs for exact payload & signing method. Use merchant id/key/secret from dashboard.
  Docs: https://developers.binance.com/docs/binance-pay
*/
app.post('/api/checkout/binance', upload.single('proof'), async (req, res) => {
  try {
    const { planId, price } = req.body;
    // Save proof file path if needed
    const proofPath = req.file ? req.file.path : null;

    // Example: build payload
    const payload = {
      merchantTradeNo: `mtrade_${Date.now()}`,
      totalAmount: String(Math.round(parseFloat(price) * 100) / 100),
      currency: "USD",
      productName: `Plan ${planId}`,
      // callback URLs you configure in Binance dashboard
      notifyUrl: `${req.protocol}://${req.get('host')}/webhook/binance`
    };

    // Sign & call Binance Pay endpoint (pseudocode - adapt per docs)
    const timestamp = Date.now().toString();
    const bodyStr = JSON.stringify(payload);
    const preHash = `${process.env.BINANCE_PAY_MERCHANT_ID}\n${timestamp}\n${process.env.BINANCE_PAY_API_KEY}\n${bodyStr}`;
    const signature = crypto.createHmac('sha512', process.env.BINANCE_PAY_API_SECRET).update(preHash).digest('hex');

    const headers = {
      'BinancePay-Timestamp': timestamp,
      'BinancePay-Nonce': crypto.randomBytes(16).toString('hex'),
      'BinancePay-Certificate-SN': process.env.BINANCE_PAY_API_KEY,
      'Content-Type': 'application/json',
      'BinancePay-Signature': signature
    };

    // Actual URL and payload structure depend on Binance docs (merchant create order endpoint).
    const binanceResp = await axios.post('https://bpay.binanceapi.com/binancepay/openapi/v2/order', bodyStr, { headers });
    // Save binanceResp.data to DB (pending)
    return res.json({ success: true, data: binanceResp.data });
  } catch (err) {
    console.error(err.response?.data || err.message);
    return res.status(500).json({ message: err.message });
  }
});

app.post('/webhook/binance', bodyParser.json(), (req,res) => {
  // Verify signature per Binance webhook docs, then mark order as paid.
  console.log('Binance webhook', req.body);
  res.json({received:true});
});

/* -------------------------
   Cash App Pay route
   ------------------------- */
/*
  Cash App Pay is a server-side integration. Use their Network API & Pay Kit.
  See Cash App Pay docs for required request signing and flows. This is the skeleton.
*/
app.post('/api/checkout/cashapp', upload.single('proof'), async (req, res) => {
  try {
    const { planId, price } = req.body;
    // Save proof file
    const proofPath = req.file ? req.file.path : null;

    // Build Cash App payment request using their Network API - pseudocode:
    const body = {
      amount: { currency: "USD", amount: String(price) },
      merchantReferenceId: `mref_${Date.now()}`,
      // other required fields...
    };

    // Sign & call Cash App endpoint using your client credentials
    // Example: axios.post('https://api.cash.app/payments', body, { headers: signedHeaders })
    // For this skeleton we return a placeholder
    return res.json({ success: true, message: "Submitted to Cash App for verification (skeleton)." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: err.message });
  }
});

app.post('/webhook/cashapp', bodyParser.json(), (req,res) => {
  // Validate webhook signature, then mark order paid.
  console.log('CashApp webhook', req.body);
  res.json({received:true});
});
// ====== EXPORT FOR VERCEL ======
module.exports = app;
