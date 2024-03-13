const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const router = express.Router();
const storeAuth = require('../middleware/store.auth');
const userAuth = require('../middleware/user.auth');
const secretkey = '1234';



const storeSchema = new mongoose.Schema({
    name: String,
    address: String,
    longitude: Number,
    latitude: Number,
    phoneNumbers: {
      type: [Number],
      required: false
    },
    landlines: {
      type: [Number],
      required: false
    },
    whatsappNumber: {
      type: Number,
      required: false
    },
    category: String,
    email: String,
    facebookPage: {
      type: String,
      required: false
    },
    facebookUsername: {
      type: String,
      required: false
    },
    instagramAccount: {
      type: String,
      required: false
    },
    instagramUsername: {
      type: String,
      required: false
    },
    password: String
  });

const Store = mongoose.model('Store', storeSchema);

  // signup store
router.post('/signup/store', async (req, res) => {
    const {
      name, latitude, longitude, phoneNumbers, landlines, address, email,whatsappNumber ,instagramAccount, instagramUsername, facebookPage,facebookUsername,category, password,
    } = req.body;
  
    const hashedPassword = await bcrypt.hash(password, 10);
    const store = new Store({
      name, latitude, longitude, phoneNumbers, landlines, address, email,whatsappNumber ,instagramAccount, instagramUsername, facebookPage,facebookUsername,category, password: hashedPassword,
    });
    await store.save();
  
    res.send('تم التسجيل بنجاح');
  });
  
  // login store
router.post('/login/store', async (req, res) => {
    const { email, password } = req.body;
    const store = await Store.findOne({ email });
  
    if (!store) {
      return res.status(401).send('فشل تسجيل الدخول');
    }
  
    const isValidPassword = await bcrypt.compare(password, store.password);
    if (!isValidPassword) {
      return res.status(401).send('فشل تسجيل الدخول');
    }
  
    const token = jwt.sign({ email: store.email }, secretkey);
    res.status(200).json({token , id: store._id});
  })
  
// حماية الوصول باستخدام التوكن
router.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'Protected route' });
});

// Middleware للتحقق من صحة التوكن
function verifyToken(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, '1234', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        req.user = decoded;

      
        User.findOne({ randomCode: req.user.randomCode }, (err, user) => {
            if (err) {
                return res.status(500).json({ message: 'Internal Server Error' });
            }

            if (!user || user.expirationDate < new Date()) {
                return res.status(401).json({ message: 'Unauthorized' });
            }

            next();
        });
    });
}


  
  module.exports.Store = Store;
  module.exports.storeRouter = router;

