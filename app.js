const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyparser = require('body-parser');
const secretkey = '1234';
const {storeRouter} = require('./routes/store');
const path = require('path');
const userAuth = require('./middleware/user.auth');

const app = express();
app.use(bodyparser.json());
app.use(bodyparser.urlencoded({ extended: true }));


mongoose.connect('mongodb+srv://ghaithbirkdar:c4a@cluster0.jb1c741.mongodb.net/dalelcom?retryWrites=true&w=majority', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("mongodb connect success.");
    app.listen(3003)
  })
  .catch(err => {
    console.log(err)
  });

const UserSchema = new mongoose.Schema({
  name: String,
  phone: Number,
  email: String,
  Latitude: Number,
  Longitude: Number,
  password: String,
  resetPasswordCode: {
    type: String,
    default: null
  }
});
const User = mongoose.model('User', UserSchema);



function generateRandomCode() {
  return Math.floor(1000 + Math.random() * 9000);
}


// signup user
app.post('/signup', async (req, res) => {
  try {
    const password1 = req.body.password
    if (password1) {
      const hashedPassword = await bcrypt.hash(password1, 10);
      const user = new User({
        name: req.body.name,
        phone: req.body.phone,
        email: req.body.email,
        Latitude: req.body.Latitude,
        Longitude: req.body.Longitude,
        password: hashedPassword
      });
      await user.save();
      res.status(200).send({ message: 'تم انشاء الحساب بنجاح' });
    } else {
      res.status(400).send({ error: 'كلمة المرور مطلوبة' });
    }
  } catch (error) {
    console.error('Error occurred during signup:', error);
    res.status(500).send({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

//login user
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    $or: [
      { phone: req.body.phone },
      { email: req.body.email }
    ]
  });
  if (user == null) {
    return res.status(400).send('Cannot find user');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const token = jwt.sign({ username: req.body.username }, secretkey);
      res.status(200).json({token, id: user._id});
    } else {
      res.send('Not Allowed');
    }
  } catch {
    res.status(500).send();
  }
});
//forgetpassword
app.post('/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    const randomCode = generateRandomCode(); // Generate random code
    user.resetPasswordCode = randomCode;
    await user.save();
    console.log(randomCode);
    sendResetPasswordCode(user.email, randomCode); // Send the code to the user
    return res.status(200).json({ message: "Reset code sent successfully" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});
//changepassword
app.post('/change-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email, resetPasswordCode: req.body.resetPasswordCode });
    if (!user) {
      return res.status(400).json({ message: "Invalid reset code" });
    }
    user.password = req.body.newPassword;
    user.resetPasswordCode = null;
    await user.save();
    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.use(storeRouter)

app.listen(3000, () => console.log('Server started'));