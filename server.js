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
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const fetch = require('node-fetch'); // si ou bezwen pou Node <18

// ====== CONFIG ======
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
const upload = multer({ dest: 'uploads/' });

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const s3 = new aws.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.S3_REGION
});
const twClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'berryxoe@gmail.com';

// ====== MongoDB ======
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=>console.log('MongoDB connected'))
  .catch(err=>console.error('MongoDB error:', err));

// ====== Mock DB ======
let user = { username: "JohnDoe", about: "Hello!" };

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

// ====== ROUTES ======

// Home
app.get('/', (req, res) => {
  res.sendFile(__dirname + 'index.html');
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
let orders = { "12345": { id:"12345", name:"Jean Ray", email:"client@example.com", total:39.99, deliveryDate:"2025-11-13", deliveryTime:"14:30", tracking:["Commande reçue"] } };
app.get("/orders/:id",(req,res)=>{
  const order = orders[req.params.id];
  if(!order) return res.status(404).json({ error:"Not found" });
  res.json(order);
});
app.post("/orders/update", async (req,res)=>{
  const { id,date,time } = req.body;
  const order = orders[id];
  if(!order) return res.json({ success:false, message:"Commande introuvable" });
  order.deliveryDate=date;
  order.deliveryTime=time;
  const msg=`Livraison reprogrammée au ${date} à ${time}`;
  order.tracking.push(msg);

  // Email notification
  const transporter = nodemailer.createTransport({ service:"gmail", auth:{ user:"votreadmin@gmail.com", pass:"motdepasseapp" } });
  await transporter.sendMail({ from:"Dawens Library <berryxoe@gmail.com>", to:order.email, subject:"Mise à jour de votre livraison 📦", text:`Bonjour ${order.name},\n\n${msg}\n\nMerci.\n— L’équipe Dawens Library` });
  res.json({ success:true });
});

// --- Payment proof + verification ---
async function getAccessToken(){
  const formData = new URLSearchParams();
  formData.append('client_id', process.env.CLIENT_ID);
  formData.append('client_secret', process.env.CLIENT_SECRET);
  formData.append('grant_type', 'client_credentials');
  const res = await fetch("https://api.moncash.natcash.com/oauth/token",{ method:"POST", body:formData });
  if(!res.ok) throw new Error("Erreur obtention token OAuth");
  const data = await res.json();
  return data.access_token;
}
async function verifyPayment(token,orderId){
  const res = await fetch(`https://api.moncash.natcash.com/V1/RetrieveTransactionPayment?reference=${orderId}`, { method:"GET", headers:{ "Authorization":`Bearer ${token}` }});
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
      return res.json({ status:"success", message:"Paiement vérifié et resi enregistré" });
    } else {
      fs.unlinkSync(req.file.path);
      return res.json({ status:"error", message:result.message });
    }
  }catch(err){ res.status(500).json({ status:"error", message:err.message }); }
});

// --- Gemini AI via Python ---
app.post('/api/gemini', async (req,res)=>{
  try{
    const { prompt } = req.body;
    if(!prompt) return res.status(400).json({ error:'No prompt' });
    const python = spawn('python3',['gemini_ai.py',prompt]);
    let output='';
    python.stdout.on('data', data=>output+=data.toString());
    python.stderr.on('data', err=>console.error('Python error:', err.toString()));
    python.on('close', code=>{
      try{
        const parsed = JSON.parse(output);
        res.json(parsed);
      }catch(err){ res.status(500).json({ error:'Error parsing Gemini response' }); }
    });
  }catch(err){ res.status(500).json({ error:'Server error' }); }
});

// --- ChatGPT ---
app.post('/api/chat', async (req,res)=>{
  const { prompt } = req.body;
  try{
    const response = await fetch('https://api.openai.com/v1/chat/completions',{
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'Authorization':`Bearer ${process.env.OPENAI_KEY}` },
      body: JSON.stringify({ model:"gpt-3.5-turbo", messages:[{role:"user",content:prompt}], temperature:0.7, max_tokens:250 })
    });
    const data = await response.json();
    const reply = data.choices[0].message.content.trim();
    res.json({ reply });
  }catch(err){ console.error(err); res.status(500).json({ reply:"Erreur serveur" }); }
});

// --- Stripe Checkout ---
app.post("/create-checkout-session", async (req,res)=>{
  try{
    const { items,email,currency } = req.body;
    if(!items || items.length===0) return res.json({ url:"https://buy.stripe.com/test_aFa14g8IF8Xb8hv4Kh5Ne00" });
    const session = await stripe.checkout.sessions.create({
      payment_method_types:["card"],
      mode:"payment",
      customer_email:email,
      line_items: items.map(i=>({ price_data:{ currency:currency||"usd", product_data:{name:i.name}, unit_amount:i.amount }, quantity:i.quantity })),
      metadata:{ items:JSON.stringify(items) },
      success_url:'http://localhost:5000/success.html?session_id={CHECKOUT_SESSION_ID}',
      cancel_url:'http://localhost:5000/cancel.html'
    });
    res.json({ url:session.url });
  }catch(err){ console.error(err); res.status(500).json({ error:err.message }); }
});

// --- Stripe Webhook ---
app.post("/webhook", express.raw({ type:"application/json" }), async (req,res)=>{
  const sig = req.headers["stripe-signature"];
  let event;
  try{ event = stripe.webhooks.constructEvent(req.body,sig,process.env.STRIPE_WEBHOOK_SECRET); } 
  catch(err){ console.error("Webhook failed:",err.message); return res.status(400).send(`Webhook Error: ${err.message}`); }
  if(event.type==="checkout.session.completed"){
    const session = event.data.object;
    const email = session.customer_email;
    let purchasedItems = [];
    try{ purchasedItems = JSON.parse(session.metadata.items || "[]"); } catch(e){ console.error(e); }
    let itemsHtml = purchasedItems.map(item=>`<tr><td style="padding:10px;"><img src="${item.img}" width="60" alt="${item.name}"></td><td style="padding:10px;">${item.name}</td><td style="padding:10px;">${item.quantity}</td><td style="padding:10px;">$${(item.amount/100).toFixed(2)}</td></tr>`).join("");
    const mailHtml = `<div style="font-family:sans-serif;line-height:1.6;"><h2 style="color:#4CAF50;">✅ Payment Successful!</h2><p>Thank you! Order received.</p><table><thead><tr><th>Image</th><th>Product</th><th>Qty</th><th>Price</th></tr></thead><tbody>${itemsHtml}</tbody></table><p>Total: $${(session.amount_total/100).toFixed(2)}</p><p>Email: ${email}</p></div>`;
    const transporter = nodemailer.createTransport({ service:"gmail", auth:{ user:process.env.EMAIL_USER, pass:process.env.EMAIL_PASS } });
    try{ await transporter.sendMail({ from:`"DaveTopUp" <${process.env.EMAIL_USER}>`, to:email, subject:"✅ Payment Confirmation - DaveTopUp", html:mailHtml }); } catch(e){ console.error(e); }
  }
  res.status(200).end();
});

// --- Admin ---
app.post('/api/admin/login', async (req,res)=>{
  const { username,password } = req.body;
  if(username==='admin' && password==='password123'){
    const token = jwt.sign({ username:'admin',role:'admin' }, process.env.JWT_SECRET,{ expiresIn:'12h' });
    return res.json({ token });
  }
  res.status(401).json({ error:'Invalid credentials' });
});
app.get('/api/admin/transactions', adminAuth, async (req,res)=>res.json(await Transaction.find().sort({ createdAt:-1 })));
app.post('/api/admin/payout', adminAuth, async (req,res)=>{
  try{
    const { txId,note } = req.body;
    const tx = await Transaction.findById(txId);
    if(!tx) return res.status(404).json({ error:'Transaction not found' });
    if(tx.status!=='pending') return res.status(400).json({ error:'Transaction not pending' });
    tx.status='completed'; tx.payoutNote=note; tx.payoutAt=new Date();
    await tx.save();
    res.json({ message:'Payout completed', txId:tx.id });
  }catch(err){ console.error(err); res.status(500).json({ error:err.message }); }
});
app.post('/api/admin/payout-bulk', adminAuth, async (req,res)=>{
  try{
    const { txIds } = req.body;
    if(!Array.isArray(txIds)) return res.status(400).json({ error:'txIds must be array' });
    const updated = await Transaction.updateMany({ _id:{ $in:txIds }, status:'pending' },{ $set:{ status:'completed', payoutAt:new Date() } });
    res.json({ message:`Bulk payout done for ${updated.modifiedCount} transactions` });
  }catch(err){ console.error(err); res.status(500).json({ error:err.message }); }
});

// --- Contact ---
const mailer = nodemailer.createTransport({ host:process.env.SMTP_HOST, port:process.env.SMTP_PORT||465, secure:true, auth:{ user:process.env.SMTP_USER, pass:process.env.SMTP_PASS } });
app.post('/api/contact', async (req,res)=>{
  try{
    const { adminSubject, adminBody, payload } = req.body;
    await mailer.sendMail({ from:`"DavToUp Contact" <${process.env.SMTP_USER}>`, to:ADMIN_EMAIL, subject:adminSubject||'New message', text:adminBody||JSON.stringify(payload,null,2) });
    res.status(200).json({ok:true,message:'Email sent'});
  }catch(err){ console.error(err); res.status(500).json({ error:'Error sending email' }); }
});

// ====== Start server ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
