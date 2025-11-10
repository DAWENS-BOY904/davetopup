// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Stripe = require('stripe');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- MongoDB connection ---
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(()=>console.log('MongoDB connected'))
.catch(err=>console.error('MongoDB error:', err));

// --- Transaction schema ---
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

// --- Middleware: admin auth JWT ---
function adminAuth(req, res, next){
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

// --- Routes ---

// Serve index.html for all frontend routes
app.get('/*', (req,res)=>{
  res.sendFile(path.join(__dirname,'public','index.html'));
});

// Stripe Checkout
app.post('/api/create-checkout-session', async (req,res)=>{
  try{
    const { cart, billing } = req.body;
    if(!cart || !cart.length) return res.status(400).json({ error:'Cart empty' });

    const line_items = cart.map(item=>({
      price_data:{
        currency:'usd',
        product_data:{ name:item.name, images:[item.image||'https://i.pravatar.cc/72'] },
        unit_amount: Math.round((item.price||0)*100)
      },
      quantity:item.quantity||1
    }));

    const session = await stripe.checkout.sessions.create({
      payment_method_types:['card'],
      line_items,
      mode:'payment',
      customer_email: billing.email,
      success_url:`${req.headers.origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:`${req.headers.origin}/cancel.html`
    });

    res.json({ url: session.url });
  }catch(err){
    console.error(err);
    res.status(500).json({ error:err.message });
  }
});

// Admin endpoints
app.get('/api/admin/transactions', adminAuth, async (req,res)=>{
  const txs = await Transaction.find().sort({ createdAt:-1 });
  res.json(txs);
});

app.post('/api/admin/payout', adminAuth, async (req,res)=>{
  try{
    const { txId, note } = req.body;
    const tx = await Transaction.findById(txId);
    if(!tx) return res.status(404).json({ error:'Transaction not found' });
    if(tx.status !== 'pending') return res.status(400).json({ error:'Transaction not pending' });

    tx.status='completed';
    tx.payoutNote = note;
    tx.payoutAt = new Date();
    await tx.save();

    res.json({ message:'Payout completed', txId: tx.id });
  }catch(err){
    console.error(err);
    res.status(500).json({ error:err.message });
  }
});

app.post('/api/admin/payout-bulk', adminAuth, async (req,res)=>{
  try{
    const { txIds } = req.body;
    if(!Array.isArray(txIds)) return res.status(400).json({ error:'txIds must be array' });

    const updated = await Transaction.updateMany(
      { _id: { $in: txIds }, status:'pending' },
      { $set: { status:'completed', payoutAt:new Date() } }
    );
    res.json({ message:`Bulk payout done for ${updated.modifiedCount} transactions` });
  }catch(err){
    console.error(err);
    res.status(500).json({ error:err.message });
  }
});

app.post('/api/admin/login', async (req,res)=>{
  const { username, password } = req.body;
  if(username==='admin' && password==='password123'){
    const token = jwt.sign({ username:'admin', role:'admin' }, process.env.JWT_SECRET, { expiresIn:'12h' });
    return res.json({ token });
  }
  res.status(401).json({ error:'Invalid credentials' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
